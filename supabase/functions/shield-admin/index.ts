// Clarivise Shield - Admin API
// Powers the dashboard: stats, review queue, settings, allow/blocklists.
//
// Auth: passwordless email OTP -> short-lived signed JWT (HS256, SHIELD_ADMIN_SECRET).
//   POST /login   { email }          -> emails a 6-digit code (10 min expiry)
//   POST /verify  { email, code }    -> returns { token } on success
//   All other routes require:  Authorization: Bearer <token>
//
// Operating model is MARKING (non-destructive): mail is delivered then tagged.
// The "quarantine" table is a review queue of flagged messages (not held mail);
// release/delete update review status only.

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { create, getNumericDate, verify } from 'https://deno.land/x/djwt@v3.0.2/mod.ts'

const SUPABASE_URL         = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
const SHIELD_ADMIN_SECRET  = Deno.env.get('SHIELD_ADMIN_SECRET')!
const RESEND_API_KEY       = Deno.env.get('RESEND_API_KEY') ?? ''

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
}

// HMAC key for signing/verifying admin JWTs.
const JWT_KEY = await crypto.subtle.importKey(
  'raw',
  new TextEncoder().encode(SHIELD_ADMIN_SECRET),
  { name: 'HMAC', hash: 'SHA-256' },
  false,
  ['sign', 'verify'],
)
const TOKEN_TTL_SECONDS = 8 * 60 * 60

function genCode(): string {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000
  return n.toString().padStart(6, '0')
}
async function hashCode(code: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code + ':' + SHIELD_ADMIN_SECRET))
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('')
}
async function makeToken(admin: { email: string; org_id: string; role?: string }): Promise<string> {
  return await create(
    { alg: 'HS256', typ: 'JWT' },
    { sub: admin.email, email: admin.email, org_id: admin.org_id, role: admin.role ?? 'admin', exp: getNumericDate(TOKEN_TTL_SECONDS) },
    JWT_KEY,
  )
}
async function sendOtpEmail(email: string, code: string): Promise<void> {
  if (!RESEND_API_KEY) { console.error('RESEND_API_KEY not set; cannot send OTP'); return }
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: 'Clarivise Shield <onboarding@resend.dev>',
        to: [email],
        subject: 'Your Clarivise Shield sign-in code',
        html: `<div style="font-family:Segoe UI,Arial,sans-serif;color:#1b2330">
          <h2 style="color:#1F4E79">Clarivise Shield sign-in</h2>
          <p>Use this code to sign in to the admin dashboard:</p>
          <p style="font-size:30px;font-weight:700;letter-spacing:6px;color:#2E75B6">${code}</p>
          <p style="color:#667">This code expires in 10 minutes. If you didn't request it, you can ignore this email.</p>
        </div>`,
      }),
    })
  } catch (e) { console.error('OTP email failed', e) }
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS })

  const url  = new URL(req.url)
  const path = url.pathname.replace('/shield-admin', '')
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

  // ── Public auth routes ────────────────────────────────────────────────────
  // POST /login -> email a one-time code (always returns ok to avoid enumeration)
  if (path === '/login' && req.method === 'POST') {
    const body = await req.json().catch(() => ({}))
    const email = String(body.email ?? '').trim().toLowerCase()
    if (!email) return json({ error: 'Email required' }, 400)
    const { data: admin } = await supabase
      .from('shield_admins')
      .select('id, email, org_id, shield_organizations(active)')
      .eq('email', email)
      .maybeSingle()
    const orgActive = !admin?.shield_organizations || (admin.shield_organizations as { active?: boolean }).active !== false
    if (admin && orgActive) {
      const code = genCode()
      const code_hash = await hashCode(code)
      const expires_at = new Date(Date.now() + 10 * 60 * 1000).toISOString()
      await supabase.from('shield_admin_otp').delete().eq('email', email)
      await supabase.from('shield_admin_otp').insert({ email, code_hash, expires_at })
      await sendOtpEmail(email, code)
    }
    return json({ ok: true }, 200)
  }

  // POST /verify -> exchange a valid code for a signed JWT
  if (path === '/verify' && req.method === 'POST') {
    const body = await req.json().catch(() => ({}))
    const email = String(body.email ?? '').trim().toLowerCase()
    const code  = String(body.code ?? '').trim()
    if (!email || !code) return json({ error: 'Email and code required' }, 400)
    const { data: otp } = await supabase
      .from('shield_admin_otp').select('*').eq('email', email)
      .order('created_at', { ascending: false }).limit(1).maybeSingle()
    if (!otp) return json({ error: 'Invalid or expired code' }, 401)
    if (new Date(otp.expires_at) < new Date()) {
      await supabase.from('shield_admin_otp').delete().eq('email', email)
      return json({ error: 'Code expired - request a new one' }, 401)
    }
    if ((otp.attempts ?? 0) >= 5) {
      await supabase.from('shield_admin_otp').delete().eq('email', email)
      return json({ error: 'Too many attempts - request a new code' }, 429)
    }
    if ((await hashCode(code)) !== otp.code_hash) {
      await supabase.from('shield_admin_otp').update({ attempts: (otp.attempts ?? 0) + 1 }).eq('id', otp.id)
      return json({ error: 'Invalid code' }, 401)
    }
    await supabase.from('shield_admin_otp').delete().eq('email', email)
    const { data: admin } = await supabase
      .from('shield_admins').select('*, shield_organizations(*)').eq('email', email).single()
    if (!admin) return json({ error: 'Unauthorized' }, 401)
    await supabase.from('shield_admins').update({ last_login: new Date().toISOString() }).eq('id', admin.id)
    const token = await makeToken(admin)
    return json({
      token,
      expires_in: TOKEN_TTL_SECONDS,
      admin: { email: admin.email, role: admin.role },
      org: { name: admin.shield_organizations?.name },
    }, 200)
  }

  // ── Authenticated routes (verify signed JWT) ──────────────────────────────
  const authHeader = req.headers.get('Authorization') ?? ''
  const bearer = authHeader.replace('Bearer ', '').trim()
  if (!bearer) return json({ error: 'Unauthorized' }, 401)

  let claims: Record<string, unknown>
  try { claims = await verify(bearer, JWT_KEY) }
  catch { return json({ error: 'Invalid or expired token' }, 401) }

  const email = String(claims.email ?? '')
  const { data: admin } = await supabase
    .from('shield_admins')
    .select('*, shield_organizations(*)')
    .eq('email', email)
    .single()
  if (!admin) return json({ error: 'Unauthorized' }, 401)
  const orgId = admin.org_id

  // GET /stats
  if (path === '/stats' && req.method === 'GET') {
    const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
    const [total, verdicts, quarantine] = await Promise.all([
      supabase.from('shield_scan_log').select('*', { count: 'exact', head: true }).eq('org_id', orgId).gte('created_at', since),
      supabase.from('shield_scan_log').select('verdict').eq('org_id', orgId).gte('created_at', since),
      supabase.from('shield_quarantine').select('*', { count: 'exact', head: true }).eq('org_id', orgId).eq('status', 'pending'),
    ])
    const counts = { SAFE: 0, SPAM: 0, SUSPICIOUS: 0, PHISHING: 0 }
    for (const row of (verdicts.data ?? [])) {
      const v = row.verdict as keyof typeof counts
      if (counts[v] !== undefined) counts[v]++
    }
    return json({ total_scanned: total.count ?? 0, quarantine_pending: quarantine.count ?? 0, verdicts: counts, threat_rate: total.count ? Math.round(((counts.PHISHING + counts.SUSPICIOUS) / total.count) * 100) : 0 }, 200)
  }

  // GET /scans
  if (path === '/scans' && req.method === 'GET') {
    const limit   = parseInt(url.searchParams.get('limit')  ?? '50')
    const offset  = parseInt(url.searchParams.get('offset') ?? '0')
    const verdict = url.searchParams.get('verdict')
    let query = supabase.from('shield_scan_log').select('*').eq('org_id', orgId).order('created_at', { ascending: false }).range(offset, offset + limit - 1)
    if (verdict) query = query.eq('verdict', verdict)
    const { data, error } = await query
    if (error) return json({ error: error.message }, 500)
    return json({ scans: data }, 200)
  }

  // GET /quarantine (review queue of flagged messages)
  if (path === '/quarantine' && req.method === 'GET') {
    const { data, error } = await supabase.from('shield_quarantine').select('*').eq('org_id', orgId).eq('status', 'pending').order('created_at', { ascending: false })
    if (error) return json({ error: error.message }, 500)
    return json({ quarantine: data }, 200)
  }

  // POST /quarantine/:id/release - mark a flagged item reviewed/cleared
  const releaseMatch = path.match(/^\/quarantine\/([\w-]+)\/release$/)
  if (releaseMatch && req.method === 'POST') {
    const body = await req.json().catch(() => ({}))
    const { error } = await supabase.from('shield_quarantine').update({ status: 'released', reviewed_by: admin.email, reviewed_at: new Date().toISOString(), release_notes: body.notes ?? '' }).eq('id', releaseMatch[1]).eq('org_id', orgId)
    if (error) return json({ error: error.message }, 500)
    return json({ success: true }, 200)
  }

  // POST /quarantine/:id/delete - dismiss a flagged item from the review queue
  const deleteMatch = path.match(/^\/quarantine\/([\w-]+)\/delete$/)
  if (deleteMatch && req.method === 'POST') {
    const { error } = await supabase.from('shield_quarantine').update({ status: 'deleted', reviewed_by: admin.email, reviewed_at: new Date().toISOString() }).eq('id', deleteMatch[1]).eq('org_id', orgId)
    if (error) return json({ error: error.message }, 500)
    return json({ success: true }, 200)
  }

  // GET /allowlist
  if (path === '/allowlist' && req.method === 'GET') {
    const { data } = await supabase.from('shield_allowlist').select('*').eq('org_id', orgId).order('created_at', { ascending: false })
    return json({ allowlist: data }, 200)
  }

  // POST /allowlist
  if (path === '/allowlist' && req.method === 'POST') {
    const body = await req.json()
    const { error } = await supabase.from('shield_allowlist').insert({ org_id: orgId, type: body.type, value: body.value.toLowerCase(), added_by: admin.email, note: body.note })
    if (error) return json({ error: error.message }, 500)
    return json({ success: true }, 200)
  }

  // DELETE /allowlist/:id
  const allowlistDel = path.match(/^\/allowlist\/([\w-]+)$/)
  if (allowlistDel && req.method === 'DELETE') {
    await supabase.from('shield_allowlist').delete().eq('id', allowlistDel[1]).eq('org_id', orgId)
    return json({ success: true }, 200)
  }

  // GET /blocklist
  if (path === '/blocklist' && req.method === 'GET') {
    const { data } = await supabase.from('shield_blocklist').select('*').eq('org_id', orgId).order('created_at', { ascending: false })
    return json({ blocklist: data }, 200)
  }

  // POST /blocklist
  if (path === '/blocklist' && req.method === 'POST') {
    const body = await req.json()
    const { error } = await supabase.from('shield_blocklist').insert({ org_id: orgId, type: body.type, value: body.value.toLowerCase(), added_by: admin.email, note: body.note })
    if (error) return json({ error: error.message }, 500)
    return json({ success: true }, 200)
  }

  // DELETE /blocklist/:id
  const blocklistDel = path.match(/^\/blocklist\/([\w-]+)$/)
  if (blocklistDel && req.method === 'DELETE') {
    await supabase.from('shield_blocklist').delete().eq('id', blocklistDel[1]).eq('org_id', orgId)
    return json({ success: true }, 200)
  }

  // GET /settings
  if (path === '/settings' && req.method === 'GET') {
    const org = admin.shield_organizations
    return json({ name: org.name, tenant_domain: org.tenant_domain, it_security_email: org.it_security_email, quarantine_threshold: org.quarantine_threshold, custom_prompt: org.custom_prompt }, 200)
  }

  // PUT /settings
  if (path === '/settings' && req.method === 'PUT') {
    const body = await req.json()
    const { error } = await supabase.from('shield_organizations').update({ it_security_email: body.it_security_email, quarantine_threshold: body.quarantine_threshold, custom_prompt: body.custom_prompt, updated_at: new Date().toISOString() }).eq('id', orgId)
    if (error) return json({ error: error.message }, 500)
    return json({ success: true }, 200)
  }

  return json({ error: 'Not found' }, 404)
})

function json(body: unknown, status: number) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  })
}
