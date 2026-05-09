// Clarivise Shield - Daily Summary Email
// Scheduled via pg_cron to run daily at 7am MT (2pm UTC)

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const SUPABASE_URL         = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
const RESEND_API_KEY       = Deno.env.get('RESEND_API_KEY')!

serve(async (_req) => {
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

  const { data: orgs } = await supabase
    .from('shield_organizations')
    .select('id, name, tenant_domain, it_security_email')
    .eq('active', true)

  if (!orgs || orgs.length === 0) {
    return new Response('No active orgs', { status: 200 })
  }

  for (const org of orgs) {
    if (!org.it_security_email) continue

    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()

    const { data: scans } = await supabase
      .from('shield_scan_log')
      .select('verdict, phishing_score, spam_score, sender, subject, actioned, created_at')
      .eq('org_id', org.id)
      .gte('created_at', since)
      .order('created_at', { ascending: false })

    if (!scans || scans.length === 0) continue

    const counts = { SAFE: 0, SPAM: 0, SUSPICIOUS: 0, PHISHING: 0 }
    for (const s of scans) {
      const v = s.verdict as keyof typeof counts
      if (counts[v] !== undefined) counts[v]++
    }

    const threats    = scans.filter(s => s.verdict === 'PHISHING' || s.verdict === 'SUSPICIOUS')
    const threatRate = Math.round(((counts.PHISHING + counts.SUSPICIOUS) / scans.length) * 100)
    const dateStr    = new Date().toLocaleDateString('en-CA', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })

    const threatRows = threats.slice(0, 10).map(s =>
      `<tr style="border-bottom:1px solid #e2e8f0;">
        <td style="padding:8px 12px;color:${s.verdict === 'PHISHING' ? '#dc2626' : '#d97706'};font-weight:600;font-size:12px;">${s.verdict}</td>
        <td style="padding:8px 12px;color:#374151;font-size:12px;">${escapeHtml(s.sender ?? '')}</td>
        <td style="padding:8px 12px;color:#374151;font-size:12px;">${escapeHtml((s.subject ?? '').slice(0, 55))}</td>
        <td style="padding:8px 12px;color:#6b7280;font-size:12px;">${s.phishing_score}/100</td>
        <td style="padding:8px 12px;color:#6b7280;font-size:12px;">${s.actioned}</td>
      </tr>`
    ).join('')

    const statCards = [
      { label: 'Total Scanned', value: scans.length,       color: '#2E75B6' },
      { label: 'Phishing',      value: counts.PHISHING,    color: '#dc2626' },
      { label: 'Suspicious',    value: counts.SUSPICIOUS,  color: '#d97706' },
      { label: 'Threat Rate',   value: threatRate + '%',   color: counts.PHISHING > 0 ? '#dc2626' : '#059669' },
    ].map(s => `
      <td style="width:25%;padding:0 6px;">
        <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:16px;text-align:center;">
          <div style="font-size:26px;font-weight:700;color:${s.color};">${s.value}</div>
          <div style="font-size:11px;color:#6b7280;margin-top:3px;">${s.label}</div>
        </div>
      </td>`).join('')

    const verdictBadges = Object.entries(counts).map(([v, c]) => {
      const bg    = v === 'SAFE' ? '#dcfce7' : v === 'SPAM' ? '#fef9c3' : v === 'SUSPICIOUS' ? '#ffedd5' : '#fee2e2'
      const color = v === 'SAFE' ? '#15803d' : v === 'SPAM' ? '#854d0e' : v === 'SUSPICIOUS' ? '#c2410c' : '#b91c1c'
      return `<span style="background:${bg};color:${color};border-radius:6px;padding:5px 14px;font-size:13px;font-weight:600;margin-right:6px;display:inline-block;margin-bottom:6px;">${v}: ${c}</span>`
    }).join('')

    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:'Segoe UI',Arial,sans-serif;background:#f1f5f9;margin:0;padding:0;">
<div style="max-width:660px;margin:0 auto;padding:32px 16px;">

  <div style="background:linear-gradient(135deg,#1F4E79 0%,#2E75B6 100%);border-radius:14px;padding:28px 32px;margin-bottom:20px;">
    <h1 style="color:#fff;margin:0 0 6px;font-size:20px;letter-spacing:-0.3px;">🛡️ Clarivise Shield</h1>
    <p style="color:#bdd7ee;margin:0;font-size:13px;">Daily Security Summary &nbsp;·&nbsp; ${org.name} &nbsp;·&nbsp; ${dateStr}</p>
  </div>

  <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
    <tr>${statCards}</tr>
  </table>

  <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:20px;margin-bottom:16px;">
    <p style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#6b7280;margin:0 0 10px;">Verdict Breakdown</p>
    <div>${verdictBadges}</div>
  </div>

  ${threats.length > 0 ? `
  <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:20px;margin-bottom:16px;">
    <p style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#6b7280;margin:0 0 12px;">⚠️ Threats Detected (${threats.length})</p>
    <table width="100%" cellpadding="0" cellspacing="0">
      <thead>
        <tr style="background:#f8fafc;">
          <th style="padding:8px 12px;text-align:left;color:#6b7280;font-size:11px;font-weight:600;">Verdict</th>
          <th style="padding:8px 12px;text-align:left;color:#6b7280;font-size:11px;font-weight:600;">Sender</th>
          <th style="padding:8px 12px;text-align:left;color:#6b7280;font-size:11px;font-weight:600;">Subject</th>
          <th style="padding:8px 12px;text-align:left;color:#6b7280;font-size:11px;font-weight:600;">Risk</th>
          <th style="padding:8px 12px;text-align:left;color:#6b7280;font-size:11px;font-weight:600;">Action</th>
        </tr>
      </thead>
      <tbody>${threatRows}</tbody>
    </table>
    ${threats.length > 10 ? `<p style="font-size:11px;color:#6b7280;margin:10px 0 0;">+ ${threats.length - 10} more. Check the Shield dashboard for full details.</p>` : ''}
  </div>` : `
  <div style="background:#dcfce7;border:1px solid #86efac;border-radius:10px;padding:16px;margin-bottom:16px;text-align:center;">
    <p style="color:#15803d;font-weight:600;margin:0;font-size:14px;">✅ No threats detected in the last 24 hours</p>
  </div>`}

  <p style="font-size:11px;color:#94a3b8;text-align:center;margin:0;">Clarivise Shield &nbsp;·&nbsp; Powered by Claude AI &nbsp;·&nbsp; ${org.tenant_domain}</p>
</div>
</body></html>`

    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'Clarivise Shield <onboarding@resend.dev>',
        to: [org.it_security_email],
        subject: `🛡️ Shield Daily Summary — ${counts.PHISHING} phishing, ${counts.SUSPICIOUS} suspicious — ${new Date().toLocaleDateString('en-CA')}`,
        html,
      }),
    })

    const result = await res.json()
    console.log(`Resend response for ${org.tenant_domain}:`, JSON.stringify(result))
  }

  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json' },
  })
})

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
