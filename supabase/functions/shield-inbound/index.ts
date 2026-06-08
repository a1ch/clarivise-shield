// Clarivise Shield - Inbound Email Processor
// Receives emails from M365 mail flow rule, analyzes with Claude AI (with prompt caching),
// then logs verdict and queues quarantine action via Microsoft Graph API.

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const ANTHROPIC_API_KEY    = Deno.env.get('ANTHROPIC_API_KEY')!
const SUPABASE_URL         = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, x-shield-secret',
}

// ── System prompt (marked for caching - same on every request = 90% cost reduction) ──────────
const SYSTEM_PROMPT = `You are an enterprise email security system analyzing inbound emails for a Microsoft 365 organization. Your job is to classify every email accurately and return a structured JSON verdict.

VERDICT DEFINITIONS:
- SAFE: Legitimate email. No threats detected.
- SPAM: Unsolicited commercial email. No active threat, just unwanted.
- SUSPICIOUS: Something feels off. Unexpected sender, odd content, minor red flags.
- PHISHING: Actively attempting to steal credentials, install malware, or defraud.

KEY RULES:
1. Gift card requests of any kind = PHISHING, score 99, always.
2. Display name impersonating a known brand from a different domain = SUSPICIOUS or PHISHING.
3. Reply-To on a different domain than sender = flag as finding.
4. Lookalike domains (typosquatting, character substitution) = PHISHING.
5. Double-extension attachments (e.g. invoice.pdf.exe) = PHISHING.
6. High-risk attachments (.exe, .js, .ps1, .hta, .vbs) = PHISHING.
7. Urgent credential requests or login links = at minimum SUSPICIOUS.
8. Microsoft SafeLinks and Proofpoint URLDefense wrappers are already decoded - do not flag the wrappers.
9. Internal senders (matching the tenant domain) must not be flagged SOLELY for being internal/external - that trust ONLY suppresses unknown-external-sender suspicion. It NEVER overrides content threats. The hard rules above (1 gift cards, 2 brand impersonation, 4 lookalike domains, 5/6 dangerous attachments, 7 credential/login requests) ALWAYS apply regardless of who sent it. CRITICAL: an internal-looking sender that exhibits phishing behavior (gift card asks, password/credential/login-link requests, lookalike or external action links, urgency to act) almost always means a COMPROMISED or SPOOFED internal account - classify as PHISHING (minimum SUSPICIOUS), set phishing_score accordingly, and add a finding warning that the internal account may be compromised or its address spoofed and to verify out-of-band before acting.
10. Known Microsoft system senders (powerautomatenoreply@microsoft.com etc) = expected, lean SAFE.
11. Account creation confirmations, email verification, security alerts, and sign-up confirmations from known major platforms (Google, Microsoft, Apple, GitHub, LinkedIn, Dropbox, DocuSign, Zoom, AWS, Stripe, etc.) sent to any domain = verdict SAFE, phishing_score 5 or less. These are expected transactional emails. However, always include a finding reminding the user: if they did not initiate this action, they should contact IT Security immediately as it may indicate unauthorized account creation or credential stuffing.
12. Do NOT flag an email as SUSPICIOUS purely because a consumer/personal service email was received at a business domain. Business users routinely receive transactional emails from consumer platforms.
13. Google-owned short link domains (c.gle, goo.gl, g.co) are legitimate URL shorteners used in official Google emails — do NOT treat them as suspicious or obfuscated. If present in an email that is otherwise legitimate, note them as an informational finding only (e.g. "This email uses Google's link shortener — this is normal for Google communications") and do not increase the phishing score on this basis alone.

Write findings for a non-technical audience. Explain what the attacker is doing and how to spot it.

Respond ONLY with this exact JSON structure, no markdown, no text outside the JSON:
{
  "verdict": "SAFE" | "SPAM" | "SUSPICIOUS" | "PHISHING",
  "phishing_score": 0-100,
  "spam_score": 0-100,
  "summary": "1-2 sentence plain English summary",
  "findings": [
    {
      "flag": "Short name of the red flag",
      "explanation": "What the attacker is doing and why it fools people",
      "howToSpotIt": "How to catch this in any email"
    }
  ],
  "lesson": "One memorable sentence for the user",
  "suggested_action": "What to do right now"
}`

// ── Main handler ──────────────────────────────────────────────────────────────────────────────
serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS })
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const secret = req.headers.get('x-shield-secret') ?? ''
  if (!secret) return json({ error: 'Unauthorized' }, 401)

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

  const { data: org, error: orgErr } = await supabase
    .from('shield_organizations')
    .select('*')
    .eq('inbound_webhook_secret', secret)
    .eq('active', true)
    .single()

  if (orgErr || !org) return json({ error: 'Unauthorized' }, 401)

  let payload: Record<string, unknown>
  try { payload = await req.json() } catch { return json({ error: 'Invalid JSON' }, 400) }

  const email = payload as {
    messageId?: string; internetMessageId?: string; subject?: string
    sender?: string; recipient?: string; body?: string
    links?: Array<{ display: string; href: string; fullUrl: string; mismatch?: boolean }>
    attachments?: string[]; replyTo?: string; isExternal?: boolean; receivedAt?: string
  }

  // ── Check allowlist ───────────────────────────────────────────────────────
  const senderDomain = extractDomain(email.sender ?? '')
  const { data: allowed } = await supabase
    .from('shield_allowlist').select('id').eq('org_id', org.id)
    .or(`value.eq.${email.sender},value.eq.${senderDomain}`).limit(1)

  if (allowed && allowed.length > 0) {
    await logScan(supabase, org.id, email, { verdict: 'SAFE', phishing_score: 0, spam_score: 0, summary: 'Sender is on your organization allowlist.', findings: [], suggested_action: 'No action needed.' }, 'delivered', 0)
    return json({ verdict: 'SAFE', action: 'delivered', reason: 'allowlisted', summary: 'Sender is on your organization allowlist.', phishing_score: 0, spam_score: 0, findings: [], suggested_action: 'No action needed.' }, 200)
  }

  // ── Check blocklist ───────────────────────────────────────────────────────
  const { data: blocked } = await supabase
    .from('shield_blocklist').select('id').eq('org_id', org.id)
    .or(`value.eq.${email.sender},value.eq.${senderDomain}`).limit(1)

  if (blocked && blocked.length > 0) {
    const blockedResult = { verdict: 'PHISHING', phishing_score: 99, spam_score: 0, summary: 'Sender is on your organization blocklist.', findings: [{ flag: 'Blocked sender', explanation: 'This sender has been manually blocked by your IT security team.', howToSpotIt: 'Contact IT if you believe this is an error.' }], suggested_action: 'Email quarantined - sender is on blocklist.' }
    await logScan(supabase, org.id, email, blockedResult, 'quarantined', 0)
    await addToQuarantine(supabase, org.id, email, blockedResult)
    return json({ verdict: 'PHISHING', action: 'quarantined', reason: 'blocklisted', summary: blockedResult.summary, phishing_score: 99, spam_score: 0, findings: blockedResult.findings, suggested_action: blockedResult.suggested_action }, 200)
  }

  // ── Call Claude AI with prompt caching ────────────────────────────────────
  const userPrompt = buildUserPrompt(email, org)
  const t0 = Date.now()
  let result: Record<string, unknown>

  try {
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'prompt-caching-2024-07-31',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1500,
        system: [
          {
            type: 'text',
            text: SYSTEM_PROMPT,
            cache_control: { type: 'ephemeral' },
          }
        ],
        messages: [{ role: 'user', content: userPrompt }],
      }),
    })

    if (!anthropicRes.ok) {
      const err = await anthropicRes.json()
      throw new Error(`Anthropic ${anthropicRes.status}: ${err.error?.message}`)
    }

    const data = await anthropicRes.json()
    const text = (data.content?.[0]?.text ?? '').trim()
    result = JSON.parse(text.replace(/```json|```/g, '').trim())
  } catch (err) {
    console.error('AI analysis failed:', err)
    return json({ verdict: 'ERROR', action: 'delivered', error: (err as Error).message }, 200)
  }

  const responseTimeMs = Date.now() - t0
  const verdict = String(result.verdict ?? 'SAFE')

  let action = 'delivered'
  if (verdict === 'PHISHING') action = 'quarantined'
  else if (verdict === 'SPAM') action = 'junk'
  else if (verdict === 'SUSPICIOUS') action = 'tagged'

  if (org.quarantine_threshold === 'SUSPICIOUS' && verdict === 'SUSPICIOUS') {
    action = 'quarantined'
  }

  await logScan(supabase, org.id, email, result, action, responseTimeMs)
  if (action === 'quarantined') await addToQuarantine(supabase, org.id, email, result)

  return json({ verdict, action, summary: result.summary, phishing_score: result.phishing_score, spam_score: result.spam_score, findings: result.findings, suggested_action: result.suggested_action }, 200)
})

// ── Helpers ───────────────────────────────────────────────────────────────────────────────────
function buildUserPrompt(email: Record<string, unknown>, org: Record<string, unknown>): string {
  const links = (email.links as Array<{ display: string; href: string; mismatch?: boolean }> ?? [])
  const attachments = (email.attachments as string[] ?? [])
  const linksBlock = links.length > 0
    ? links.map(l => ` - Display: "${l.display}" -> Real domain: ${l.href}${l.mismatch ? ' WARNING: DOMAIN MISMATCH' : ''}`).join('\n')
    : '(none)'

  return `Analyze this inbound email for organization: ${org.tenant_domain}
${org.custom_prompt ? `\nOrg instructions: ${org.custom_prompt}` : ''}

Subject: ${email.subject ?? '(none)'}
From: ${email.sender ?? '(unknown)'}
To: ${email.recipient ?? '(unknown)'}
Reply-To: ${email.replyTo ?? '(same as sender)'}
External sender: ${email.isExternal ? 'YES' : 'NO or UNKNOWN'}
Received: ${email.receivedAt ?? 'unknown'}

Body:
${String(email.body ?? '(empty)').slice(0, 3000)}

Attachments: ${attachments.length > 0 ? attachments.join(', ') : '(none)'}

Links:
${linksBlock}`
}

function extractDomain(email: string): string {
  const match = email.toLowerCase().match(/@([\w.-]+)/)
  return match ? match[1] : ''
}

async function logScan(supabase: ReturnType<typeof createClient>, orgId: string, email: Record<string, unknown>, result: Record<string, unknown>, action: string, responseTimeMs: number) {
  await supabase.from('shield_scan_log').insert({
    org_id: orgId,
    message_id: email.messageId,
    internet_message_id: email.internetMessageId,
    verdict: result.verdict,
    phishing_score: result.phishing_score,
    spam_score: result.spam_score,
    summary: result.summary,
    suggested_action: result.suggested_action,
    findings: result.findings,
    sender: email.sender,
    recipient: email.recipient,
    subject: email.subject,
    has_attachments: ((email.attachments as string[]) ?? []).length > 0,
    link_count: ((email.links as unknown[]) ?? []).length,
    actioned: action,
    response_time_ms: responseTimeMs,
  })
}

async function addToQuarantine(supabase: ReturnType<typeof createClient>, orgId: string, email: Record<string, unknown>, result: Record<string, unknown>) {
  await supabase.from('shield_quarantine').insert({
    org_id: orgId,
    message_id: email.messageId,
    internet_message_id: email.internetMessageId,
    sender: email.sender,
    recipient: email.recipient,
    subject: email.subject,
    received_at: email.receivedAt,
    verdict: result.verdict,
    phishing_score: result.phishing_score,
    summary: result.summary,
    findings: result.findings,
    status: 'pending',
  })
}

function json(body: unknown, status: number) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  })
}
