-- Production-readiness security hardening (applied 2026-07-17, project eysvvjrsjbfyeuggyhey)
-- Locks down SECURITY DEFINER functions + strips leftover anon table grants.
-- Every statement is idempotent and safe to re-run.

-- 1) Pin search_path on SECURITY DEFINER trigger functions.
alter function public.link_auth_user_to_shield_admin() set search_path = public, pg_temp;
alter function public.link_existing_auth_user_on_admin_insert() set search_path = public, pg_temp;

-- 2) Trigger / event-trigger functions — never meant to be invoked via public RPC.
--    (Triggers still fire regardless of the invoker''s EXECUTE privilege.)
revoke execute on function public.link_auth_user_to_shield_admin() from anon, authenticated, public;
revoke execute on function public.link_existing_auth_user_on_admin_insert() from anon, authenticated, public;
revoke execute on function public.rls_auto_enable() from anon, authenticated, public;

-- 3) Strip leftover anon/authenticated grants on sensitive tables (RLS deny-all already
--    blocks rows; the grant is a latent leak). Backend runs as service_role (unaffected).
revoke all on
  public.shield_admin_otp, public.shield_admins, public.shield_allowlist,
  public.shield_blocklist, public.shield_organizations, public.shield_quarantine,
  public.shield_rate_limit, public.shield_scan_log
from anon, authenticated;