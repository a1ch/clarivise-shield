// Clarivise Shield - Admin API
// Powers the dashboard: stats, quarantine management, settings, allow/blocklists.

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const SUPABASE_URL         = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS })

  const url  = new URL(req.url)
  const path = url.pathname.replace('/shield-admin', '')

  const authHeader = req.headers.get('Authorization') ?? ''
  const token = authHeader.replace('Bearer ', '').trim()
  if (!token) return json({ error: 'Unauthorized' }, 401)

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

  // TODO: replace with proper JWT - for now uses admin email as token
  const { data: admin } = await supabase
    .from('shield_admins')
    .select('*, shield_organizations(*)')
    .eq('email', token)
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

  // GET /quarantine
  if (path === '/quarantine' && req.method === 'GET') {
    const { data, error } = await supabase.from('shield_quarantine').select('*').eq('org_id', orgId).eq('status', 'pending').order('created_at', { ascending: false })
    if (error) return json({ error: error.message }, 500)
    return json({ quarantine: data }, 200)
  }

  // POST /quarantine/:id/release
  const releaseMatch = path.match(/^\/quarantine\/([\w-]+)\/release$/)
  if (releaseMatch && req.method === 'POST') {
    const body = await req.json().catch(() => ({}))
    const { error } = await supabase.from('shield_quarantine').update({ status: 'released', reviewed_by: admin.email, reviewed_at: new Date().toISOString(), release_notes: body.notes ?? '' }).eq('id', releaseMatch[1]).eq('org_id', orgId)
    if (error) return json({ error: error.message }, 500)
    // TODO: call Graph API to deliver the email from M365 quarantine
    return json({ success: true }, 200)
  }

  // POST /quarantine/:id/delete
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
