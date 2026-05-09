-- Clarivise Shield - Database Schema

CREATE TABLE IF NOT EXISTS shield_organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  tenant_domain TEXT NOT NULL UNIQUE,
  m365_tenant_id TEXT,
  m365_client_id TEXT,
  m365_client_secret_enc TEXT,
  inbound_webhook_secret TEXT NOT NULL,
  it_security_email TEXT,
  quarantine_threshold TEXT DEFAULT 'PHISHING',
  custom_prompt TEXT,
  active BOOLEAN DEFAULT true,
  plan TEXT DEFAULT 'trial',
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS shield_scan_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES shield_organizations(id) ON DELETE CASCADE,
  message_id TEXT,
  internet_message_id TEXT,
  verdict TEXT NOT NULL,
  phishing_score INTEGER,
  spam_score INTEGER,
  summary TEXT,
  suggested_action TEXT,
  findings JSONB DEFAULT '[]',
  sender TEXT,
  recipient TEXT,
  subject TEXT,
  has_attachments BOOLEAN DEFAULT false,
  link_count INTEGER DEFAULT 0,
  actioned TEXT DEFAULT 'delivered',
  response_time_ms INTEGER,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_shield_scan_log_org_id ON shield_scan_log(org_id);
CREATE INDEX idx_shield_scan_log_verdict ON shield_scan_log(verdict);
CREATE INDEX idx_shield_scan_log_created_at ON shield_scan_log(created_at DESC);

CREATE TABLE IF NOT EXISTS shield_quarantine (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES shield_organizations(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES shield_scan_log(id),
  message_id TEXT NOT NULL,
  internet_message_id TEXT,
  sender TEXT,
  recipient TEXT,
  subject TEXT,
  received_at TIMESTAMPTZ,
  verdict TEXT,
  phishing_score INTEGER,
  summary TEXT,
  findings JSONB DEFAULT '[]',
  status TEXT DEFAULT 'pending',
  reviewed_by TEXT,
  reviewed_at TIMESTAMPTZ,
  release_notes TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_shield_quarantine_org_id ON shield_quarantine(org_id);
CREATE INDEX idx_shield_quarantine_status ON shield_quarantine(status);

CREATE TABLE IF NOT EXISTS shield_allowlist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES shield_organizations(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  added_by TEXT,
  note TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(org_id, type, value)
);

CREATE TABLE IF NOT EXISTS shield_blocklist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES shield_organizations(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  added_by TEXT,
  note TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(org_id, type, value)
);

CREATE TABLE IF NOT EXISTS shield_admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES shield_organizations(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT DEFAULT 'admin',
  invited_by TEXT,
  last_login TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(org_id, email)
);

CREATE TABLE IF NOT EXISTS shield_rate_limit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES shield_organizations(id) ON DELETE CASCADE,
  window_start TIMESTAMPTZ NOT NULL,
  count INTEGER DEFAULT 1,
  UNIQUE(org_id, window_start)
);
