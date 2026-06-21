-- Clarivise Shield - Admin login one-time codes (OTP)
-- Backs the email-code step of admin sign-in. Codes are stored hashed
-- (SHA-256 salted with SHIELD_ADMIN_SECRET) and expire after 10 minutes.

CREATE TABLE IF NOT EXISTS shield_admin_otp (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_shield_admin_otp_email ON shield_admin_otp(email);
CREATE INDEX IF NOT EXISTS idx_shield_admin_otp_expires ON shield_admin_otp(expires_at);
