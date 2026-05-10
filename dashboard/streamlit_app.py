"""
Clarivise Shield — Multi-Tenant Admin Dashboard
Real Supabase Auth login, per-tenant data scoping, super admin org switcher.
Handles invite signup flow via URL token params.
"""
import os
from datetime import datetime, timezone
from typing import Optional

import streamlit as st
from supabase import Client, create_client

# ── Config ─────────────────────────────────────────────────────────────────────
def _secret(name: str) -> str:
    try:
        v = st.secrets.get(name, "")
    except Exception:
        v = ""
    if v and str(v).strip():
        return str(v).strip()
    return (os.environ.get(name) or "").strip()

SUPABASE_URL      = _secret("SUPABASE_URL") or "https://eysvvjrsjbfyeuggyhey.supabase.co"
SUPABASE_ANON_KEY = _secret("SUPABASE_ANON_KEY")
SUPABASE_SVC_KEY  = _secret("SUPABASE_SERVICE_ROLE_KEY")

SB_ACCESS  = "shield_access_token"
SB_REFRESH = "shield_refresh_token"
SB_CLIENT  = "shield_anon_client"

MIN_PASSWORD_LEN = 8

def get_anon_client() -> Optional[Client]:
    if not SUPABASE_ANON_KEY:
        return None
    if SB_CLIENT not in st.session_state:
        st.session_state[SB_CLIENT] = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    return st.session_state[SB_CLIENT]

def get_svc_client() -> Optional[Client]:
    if not SUPABASE_SVC_KEY:
        return None
    return create_client(SUPABASE_URL, SUPABASE_SVC_KEY)

def get_auth_user(client: Client):
    at = st.session_state.get(SB_ACCESS)
    rt = st.session_state.get(SB_REFRESH)
    if not at or not rt:
        return None
    try:
        client.auth.set_session(at, rt)
        res = client.auth.get_user()
        user = getattr(res, "user", None)
        if user and hasattr(user, "id"):
            return user
    except Exception:
        pass
    st.session_state.pop(SB_ACCESS, None)
    st.session_state.pop(SB_REFRESH, None)
    return None

def get_admin_record(svc: Client, user_id: str) -> Optional[dict]:
    res = svc.table("shield_admins") \
        .select("*, shield_organizations(id, name, tenant_domain, plan, active)") \
        .eq("auth_user_id", user_id).limit(1).execute()
    return res.data[0] if res.data else None

# ── Theme ──────────────────────────────────────────────────────────────────────
def inject_theme():
    st.markdown("""
<style>
    :root { --ink:#0f172a; --muted:#64748b; --accent:#2E75B6; }
    .block-container { padding-top:0.5rem !important; max-width:1200px; }
    [data-testid="stAppViewContainer"] { background:#0b1929; }
    [data-testid="stMainBlockContainer"] { color:#e2e8f0; }
    [data-testid="stSidebar"] { background:#0f2035 !important; }
    section.main label, section.main [data-testid="stWidgetLabel"] p { color:#94a3b8 !important; }
    section.main [data-testid="stCaption"] { color:#64748b !important; }
    section.main [data-baseweb="input"] input,
    section.main [data-baseweb="textarea"] textarea { color:#e2e8f0 !important; -webkit-text-fill-color:#e2e8f0 !important; background:#1a3050 !important; }
    section.main [data-baseweb="select"] { background:#1a3050 !important; }
    .stat-card { background:#1a3050; border:1px solid rgba(46,117,182,.25); border-radius:12px; padding:1.25rem; text-align:center; }
    .stat-card .val { font-size:2rem; font-weight:700; line-height:1; margin-bottom:.25rem; }
    .stat-card .lbl { font-size:.75rem; color:#94a3b8; text-transform:uppercase; letter-spacing:.06em; }
    .badge-safe { background:#064e3b; color:#6ee7b7; border-radius:6px; padding:.2rem .6rem; font-size:.75rem; font-weight:700; }
    .badge-spam { background:#78350f; color:#fcd34d; border-radius:6px; padding:.2rem .6rem; font-size:.75rem; font-weight:700; }
    .badge-suspicious { background:#7c2d12; color:#fdba74; border-radius:6px; padding:.2rem .6rem; font-size:.75rem; font-weight:700; }
    .badge-phishing { background:#7f1d1d; color:#fca5a5; border-radius:6px; padding:.2rem .6rem; font-size:.75rem; font-weight:700; }
    .scan-row { background:#1a3050; border:1px solid rgba(46,117,182,.2); border-radius:10px; padding:.85rem 1rem; margin-bottom:.5rem; }
    .q-row { background:#1a1a2e; border:1px solid rgba(220,38,38,.3); border-radius:12px; padding:1rem 1.25rem; margin-bottom:.75rem; }
    .org-card { background:#1a3050; border:1px solid rgba(46,117,182,.25); border-radius:12px; padding:1rem 1.25rem; margin-bottom:.6rem; }
    .org-card .org-name { font-size:.95rem; font-weight:600; color:#e2e8f0; }
    .org-card .org-domain { font-size:.78rem; color:#94a3b8; margin-top:.15rem; }
    .pill-active { background:#064e3b; color:#6ee7b7; border-radius:999px; padding:.15rem .6rem; font-size:.7rem; font-weight:700; }
    .pill-inactive { background:#374151; color:#9ca3af; border-radius:999px; padding:.15rem .6rem; font-size:.7rem; font-weight:700; }
    .auth-box { max-width:440px; margin:4rem auto; background:#1a3050; border:1px solid rgba(46,117,182,.3); border-radius:16px; padding:2.5rem; }
</style>""", unsafe_allow_html=True)

def verdict_badge(v: str) -> str:
    cls = {"SAFE": "safe", "SPAM": "spam", "SUSPICIOUS": "suspicious", "PHISHING": "phishing"}.get(v, "safe")
    return f'<span class="badge-{cls}">{v}</span>'

def fmt_time(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%b %d %H:%M")
    except Exception:
        return ts[:16] if ts else ""

def auth_header():
    st.markdown("""
<div class="auth-box">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:1.75rem;">
    <span style="font-size:2rem;">🛡️</span>
    <div>
      <div style="font-size:1.2rem;font-weight:700;color:#fff;">Clarivise Shield</div>
      <div style="font-size:.82rem;color:#94a3b8;">Tenant Admin Dashboard</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)


# ── Invite / Set Password flow ─────────────────────────────────────────────────
def render_set_password(access_token: str, refresh_token: str):
    """Shown when a user clicks their invite link — lets them set a password."""
    auth_header()
    st.markdown("### Set your password")
    st.caption("You've been invited to Clarivise Shield. Set a password to activate your account.")

    with st.form("set_password"):
        pw  = st.text_input("New password", type="password", help=f"At least {MIN_PASSWORD_LEN} characters.")
        pw2 = st.text_input("Confirm password", type="password")
        submitted = st.form_submit_button("Activate account", use_container_width=True, type="primary")

    if submitted:
        if len(pw) < MIN_PASSWORD_LEN:
            st.error(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
            return
        if pw != pw2:
            st.error("Passwords do not match.")
            return
        anon = get_anon_client()
        if not anon:
            st.error("Configuration error — contact support.")
            return
        try:
            # Use the invite tokens to set the session then update password
            anon.auth.set_session(access_token, refresh_token)
            anon.auth.update_user({"password": pw})
            # Store session so they land on the dashboard immediately
            st.session_state[SB_ACCESS]  = access_token
            st.session_state[SB_REFRESH] = refresh_token
            # Clear the invite params from URL
            st.query_params.clear()
            st.success("Password set! Taking you to your dashboard...")
            st.rerun()
        except Exception as ex:
            msg = getattr(ex, "message", str(ex))
            st.error(f"Failed to set password: {msg}")


# ── Login ──────────────────────────────────────────────────────────────────────
def render_login():
    auth_header()

    tab_in, tab_reset = st.tabs(["Sign In", "Reset Password"])

    with tab_in:
        with st.form("login"):
            email    = st.text_input("Email", placeholder="admin@yourcompany.com")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign In", use_container_width=True, type="primary")

        if submitted:
            if not email or not password:
                st.error("Enter your email and password.")
                return
            anon = get_anon_client()
            if not anon:
                st.error("SUPABASE_ANON_KEY missing from secrets.")
                return
            try:
                res  = anon.auth.sign_in_with_password({"email": email.strip(), "password": password})
                sess = getattr(res, "session", None)
                if not sess:
                    st.error("Invalid credentials.")
                    return
                st.session_state[SB_ACCESS]  = sess.access_token
                st.session_state[SB_REFRESH] = sess.refresh_token

                # Verify shield_admins record exists
                svc  = get_svc_client()
                user = getattr(res, "user", None)
                if svc and user:
                    admin = get_admin_record(svc, str(user.id))
                    if not admin:
                        st.error("No Shield admin account found for this email. Contact your administrator.")
                        st.session_state.pop(SB_ACCESS, None)
                        st.session_state.pop(SB_REFRESH, None)
                        return
                    svc.table("shield_admins") \
                        .update({"last_login": datetime.now(timezone.utc).isoformat()}) \
                        .eq("auth_user_id", str(user.id)).execute()
                st.rerun()
            except Exception as ex:
                msg = getattr(ex, "message", str(ex))
                st.error(f"Sign in failed: {msg}")

    with tab_reset:
        st.caption("Enter your email and we'll send a reset link.")
        with st.form("reset"):
            reset_email = st.text_input("Email address")
            if st.form_submit_button("Send reset link", use_container_width=True):
                anon = get_anon_client()
                if anon and reset_email:
                    try:
                        anon.auth.reset_password_email(reset_email.strip())
                        st.success("Reset link sent — check your inbox.")
                    except Exception as ex:
                        st.error(str(ex))


# ── Super Admin: All Orgs ──────────────────────────────────────────────────────
def render_super_admin(svc: Client):
    st.markdown("## 🌐 All Organizations")
    st.caption("Super admin view — all tenants")

    tab_orgs, tab_invite = st.tabs(["Organizations", "Invite Admin"])

    with tab_orgs:
        orgs = svc.table("shield_organizations") \
            .select("*, shield_admins(email, role, last_login)") \
            .order("created_at", desc=True).execute()

        for org in (orgs.data or []):
            active_pill = '<span class="pill-active">Active</span>' if org.get("active") else '<span class="pill-inactive">Inactive</span>'
            admins     = org.get("shield_admins", [])
            admin_list = ", ".join(a["email"] for a in admins) if admins else "No admins"
            scan_count = svc.table("shield_scan_log").select("id", count="exact").eq("org_id", org["id"]).execute().count or 0

            st.markdown(f"""
<div class="org-card">
  <div class="org-name">{org['name']} &nbsp; {active_pill}</div>
  <div class="org-domain">{org.get('tenant_domain','—')} &nbsp;·&nbsp; Plan: <strong>{org.get('plan','—')}</strong> &nbsp;·&nbsp; {scan_count:,} emails scanned</div>
  <div style="font-size:.75rem;color:#64748b;margin-top:.2rem;">Admins: {admin_list}</div>
</div>""", unsafe_allow_html=True)

            c1, c2, c3 = st.columns([1, 1, 4])
            with c1:
                if st.button("View", key=f"view_{org['id']}"):
                    st.session_state["selected_org_id"]   = org["id"]
                    st.session_state["selected_org_name"] = org["name"]
                    st.rerun()
            with c2:
                label = "Deactivate" if org.get("active") else "Activate"
                if st.button(label, key=f"toggle_{org['id']}"):
                    svc.table("shield_organizations").update({"active": not org.get("active")}).eq("id", org["id"]).execute()
                    st.rerun()

        st.divider()
        if st.button("➕ New Organization"):
            st.session_state["show_new_org"] = not st.session_state.get("show_new_org", False)

        if st.session_state.get("show_new_org"):
            with st.form("new_org"):
                o1, o2 = st.columns(2)
                with o1: org_name   = st.text_input("Organization name", placeholder="Acme Corp")
                with o2: org_domain = st.text_input("Tenant domain", placeholder="acmecorp.com")
                org_email = st.text_input("IT security email", placeholder="security@acmecorp.com")
                org_plan  = st.selectbox("Plan", ["trial", "basic", "business", "enterprise"])
                if st.form_submit_button("Create", type="primary"):
                    if org_name and org_domain:
                        import secrets as _secrets
                        webhook = f"clarivise-shield-{org_domain.replace('.', '-')}-{_secrets.token_hex(8)}"
                        svc.table("shield_organizations").insert({
                            "name": org_name, "tenant_domain": org_domain,
                            "it_security_email": org_email, "plan": org_plan,
                            "inbound_webhook_secret": webhook,
                        }).execute()
                        st.session_state.pop("show_new_org", None)
                        st.success(f"✅ Created {org_name}")
                        st.rerun()

    with tab_invite:
        st.caption("The admin will receive an email to set their password and land directly in their org's dashboard.")
        orgs_list   = svc.table("shield_organizations").select("id, name").order("name").execute()
        org_options = {o["name"]: o["id"] for o in (orgs_list.data or [])}

        with st.form("invite_admin"):
            invite_org   = st.selectbox("Organization", list(org_options.keys()))
            invite_email = st.text_input("Admin email", placeholder="admin@tenant.com")
            invite_role  = st.selectbox("Role", ["admin", "viewer"])
            if st.form_submit_button("Send Invite", type="primary"):
                if invite_org and invite_email:
                    org_id   = org_options[invite_org]
                    existing = svc.table("shield_admins").select("id").eq("email", invite_email).execute()
                    if existing.data:
                        st.warning(f"{invite_email} already has an admin record.")
                    else:
                        # Insert admin record first — trigger will link auth_user_id on signup
                        svc.table("shield_admins").insert({
                            "org_id": org_id, "email": invite_email,
                            "role": invite_role,
                            "invited_by": st.session_state.get("shield_user_email", ""),
                        }).execute()
                        try:
                            svc.auth.admin.invite_user_by_email(invite_email)
                            st.success(f"✅ Invite sent to {invite_email}. They'll get an email to set their password.")
                        except Exception as ex:
                            st.success(f"✅ Admin record created for {invite_email}. Send them the dashboard URL to sign up.")
                        st.rerun()


# ── Org Dashboard ──────────────────────────────────────────────────────────────
def render_org_dashboard(svc: Client, org_id: str, org_name: str, is_super: bool, user_email: str):
    with st.sidebar:
        st.markdown("### 🛡️ Clarivise Shield")
        st.caption(f"**{org_name}**")
        st.divider()
        if is_super:
            if st.button("← All Organizations"):
                st.session_state.pop("selected_org_id", None)
                st.session_state.pop("selected_org_name", None)
                st.rerun()
            st.divider()
        tab = st.radio("Navigate",
                       ["Overview", "Scan Log", "Quarantine", "Allow/Block", "Admins", "Settings"],
                       label_visibility="collapsed")
        st.divider()
        st.caption(f"**{user_email}**")
        st.caption("Super Admin" if is_super else "Admin")
        if st.button("Sign out"):
            anon = get_anon_client()
            if anon:
                try: anon.auth.sign_out()
                except Exception: pass
            st.session_state.clear()
            st.rerun()

    titles = {
        "Overview":    ("📊 Overview",              "Last 30 days"),
        "Scan Log":    ("📋 Scan Log",               "All analyzed emails"),
        "Quarantine":  ("🔒 Quarantine",             "Emails pending review"),
        "Allow/Block": ("✅🚫 Allow / Block Lists",  "Trusted and blocked senders"),
        "Admins":      ("👥 Admins",                 "Manage who has access"),
        "Settings":    ("⚙️ Settings",               "Organization configuration"),
    }
    title, subtitle = titles.get(tab, ("Shield", ""))
    st.markdown(f"## {title}")
    st.caption(subtitle)
    st.divider()

    if   tab == "Overview":    render_overview(svc, org_id)
    elif tab == "Scan Log":    render_scans(svc, org_id)
    elif tab == "Quarantine":  render_quarantine(svc, org_id)
    elif tab == "Allow/Block": render_lists(svc, org_id)
    elif tab == "Admins":      render_admins(svc, org_id, is_super)
    elif tab == "Settings":    render_settings(svc, org_id)


# ── Overview ───────────────────────────────────────────────────────────────────
def render_overview(svc: Client, org_id: str):
    rows = svc.table("shield_scan_log").select("verdict, created_at") \
        .eq("org_id", org_id).order("created_at", desc=True).limit(1000).execute().data or []

    total    = len(rows)
    verdicts: dict = {}
    for r in rows:
        v = r.get("verdict", "SAFE")
        verdicts[v] = verdicts.get(v, 0) + 1

    q_pending  = svc.table("shield_quarantine").select("id", count="exact") \
        .eq("org_id", org_id).eq("status", "pending").execute().count or 0
    threats    = sum(verdicts.get(k, 0) for k in ("PHISHING", "SUSPICIOUS", "SPAM"))
    threat_pct = round((threats / total) * 100) if total else 0

    c1, c2, c3, c4 = st.columns(4)
    for col, val, color, label in [
        (c1, f"{total:,}",            "#2E75B6", "Emails Scanned"),
        (c2, str(q_pending),          "#dc2626", "Quarantine Pending"),
        (c3, f"{threat_pct}%",        "#d97706", "Threat Rate"),
        (c4, str(verdicts.get("PHISHING", 0)), "#dc2626", "Phishing Caught"),
    ]:
        with col:
            st.markdown(f'<div class="stat-card"><div class="val" style="color:{color};">{val}</div><div class="lbl">{label}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("**Verdict breakdown**")
    v1, v2, v3, v4 = st.columns(4)
    for col, label, color, key in [
        (v1, "SAFE",       "#059669", "SAFE"),
        (v2, "SPAM",       "#d97706", "SPAM"),
        (v3, "SUSPICIOUS", "#ea580c", "SUSPICIOUS"),
        (v4, "PHISHING",   "#dc2626", "PHISHING"),
    ]:
        count = verdicts.get(key, 0)
        pct   = round((count / total) * 100) if total else 0
        with col:
            st.markdown(f'<div class="stat-card"><div class="val" style="color:{color};">{count}</div><div class="lbl">{label} · {pct}%</div></div>', unsafe_allow_html=True)

    if st.button("🔄 Refresh"):
        st.rerun()


# ── Scan Log ───────────────────────────────────────────────────────────────────
def render_scans(svc: Client, org_id: str):
    c1, c2, c3 = st.columns([3, 1, 1])
    with c2: filter_verdict = st.selectbox("Verdict", ["All", "PHISHING", "SUSPICIOUS", "SPAM", "SAFE"])
    with c3: limit = st.selectbox("Show", [50, 100, 250], index=0)

    q = svc.table("shield_scan_log") \
        .select("id, verdict, phishing_score, subject, sender, summary, actioned, created_at") \
        .eq("org_id", org_id).order("created_at", desc=True)
    if filter_verdict != "All":
        q = q.eq("verdict", filter_verdict)

    rows = q.limit(limit).execute().data or []
    st.caption(f"{len(rows)} emails")

    for s in rows:
        badge     = verdict_badge(s.get("verdict", "SAFE"))
        score     = s.get("phishing_score")
        score_str = f" · {score}%" if score is not None else ""
        st.markdown(f"""
<div class="scan-row">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;">
    <div style="flex:1;min-width:0;">
      {badge}{score_str}
      <span style="font-size:.9rem;font-weight:600;color:#e2e8f0;margin-left:.5rem;">{s.get('subject','(no subject)')}</span>
      <div style="font-size:.78rem;color:#94a3b8;margin-top:.15rem;">{s.get('sender','')}</div>
      <div style="font-size:.78rem;color:#64748b;margin-top:.25rem;">{s.get('summary','')}</div>
    </div>
    <div style="text-align:right;flex-shrink:0;margin-left:1rem;">
      <div style="font-size:.75rem;color:#64748b;">{fmt_time(s.get('created_at',''))}</div>
      <div style="font-size:.72rem;color:#475569;margin-top:.2rem;">{s.get('actioned','delivered')}</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    if not rows:
        st.info("No scans found.")


# ── Quarantine ─────────────────────────────────────────────────────────────────
def render_quarantine(svc: Client, org_id: str):
    status_filter = st.selectbox("Status", ["pending", "released", "deleted", "all"], key="q_status")

    q = svc.table("shield_quarantine").select("*").eq("org_id", org_id).order("created_at", desc=True)
    if status_filter != "all":
        q = q.eq("status", status_filter)

    items = q.limit(100).execute().data or []
    st.caption(f"{len(items)} items")

    for item in items:
        st.markdown(f"""
<div class="q-row">
  <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.3rem;">
    {verdict_badge(item.get('verdict','PHISHING'))}
    <span style="font-size:.75rem;color:#6b7280;">{fmt_time(item.get('created_at',''))}</span>
    <span style="font-size:.72rem;color:#475569;">· {item.get('status','pending')}</span>
  </div>
  <div style="font-size:.92rem;font-weight:600;color:#e2e8f0;">{item.get('subject','(no subject)')}</div>
  <div style="font-size:.78rem;color:#94a3b8;margin-top:.2rem;">{item.get('sender','')}</div>
  <div style="font-size:.78rem;color:#6b7280;margin-top:.35rem;">{item.get('summary','')}</div>
</div>""", unsafe_allow_html=True)

        if item.get("status") == "pending":
            _, c2, c3 = st.columns([3, 1, 1])
            with c2:
                if st.button("✅ Release", key=f"rel_{item['id']}", use_container_width=True):
                    svc.table("shield_quarantine").update({
                        "status": "released",
                        "reviewed_at": datetime.now(timezone.utc).isoformat(),
                    }).eq("id", item["id"]).execute()
                    st.rerun()
            with c3:
                if st.button("🗑️ Delete", key=f"del_{item['id']}", use_container_width=True):
                    svc.table("shield_quarantine").update({
                        "status": "deleted",
                        "reviewed_at": datetime.now(timezone.utc).isoformat(),
                    }).eq("id", item["id"]).execute()
                    st.rerun()

    if not items:
        st.success("✅ Nothing here.")


# ── Allow / Block Lists ────────────────────────────────────────────────────────
def render_lists(svc: Client, org_id: str):
    tab1, tab2 = st.tabs(["✅ Allowlist", "🚫 Blocklist"])

    for tab, table_name, label in [
        (tab1, "shield_allowlist", "allowlist"),
        (tab2, "shield_blocklist", "blocklist"),
    ]:
        with tab:
            items = svc.table(table_name).select("*").eq("org_id", org_id) \
                .order("created_at", desc=True).execute().data or []
            for item in items:
                c1, c2 = st.columns([6, 1])
                with c1:
                    st.markdown(f"**{item['value']}** &nbsp; `{item['type']}` &nbsp;·&nbsp; {item.get('note','') or '—'}")
                with c2:
                    if st.button("Remove", key=f"{label}_del_{item['id']}"):
                        svc.table(table_name).delete().eq("id", item["id"]).execute()
                        st.rerun()
            st.divider()
            st.markdown(f"**Add to {label}**")
            with st.form(f"add_{label}"):
                a1, a2 = st.columns(2)
                with a1: val = st.text_input("Email or domain", placeholder="sender@example.com or example.com", key=f"{label}_val")
                with a2: typ = st.selectbox("Type", ["email", "domain"], key=f"{label}_type")
                note = st.text_input("Note (optional)", key=f"{label}_note")
                if st.form_submit_button("Add", type="primary"):
                    if val:
                        svc.table(table_name).insert({"org_id": org_id, "type": typ, "value": val.strip(), "note": note}).execute()
                        st.success(f"Added {val}")
                        st.rerun()


# ── Admins ─────────────────────────────────────────────────────────────────────
def render_admins(svc: Client, org_id: str, is_super: bool):
    admins = svc.table("shield_admins").select("*").eq("org_id", org_id).order("created_at").execute().data or []

    for admin in admins:
        last   = fmt_time(admin.get("last_login", "")) or "Never"
        linked = "✅ Linked" if admin.get("auth_user_id") else "⚠️ Pending signup"
        c1, c2 = st.columns([5, 1])
        with c1:
            st.markdown(f"**{admin['email']}** &nbsp; `{admin.get('role','admin')}` &nbsp;·&nbsp; Last login: {last} &nbsp;·&nbsp; {linked}")
        with c2:
            if not admin.get("is_super_admin"):
                if st.button("Remove", key=f"rm_{admin['id']}"):
                    svc.table("shield_admins").delete().eq("id", admin["id"]).execute()
                    st.rerun()

    st.divider()
    st.markdown("**Invite a new admin**")
    st.caption("They'll receive an email to set their password and land directly in this org's dashboard.")
    with st.form("invite_org_admin"):
        inv_email = st.text_input("Email address", placeholder="newadmin@yourcompany.com")
        inv_role  = st.selectbox("Role", ["admin", "viewer"])
        if st.form_submit_button("Send Invite", type="primary"):
            if inv_email:
                existing = svc.table("shield_admins").select("id") \
                    .eq("email", inv_email).eq("org_id", org_id).execute()
                if existing.data:
                    st.warning(f"{inv_email} is already an admin for this organization.")
                else:
                    svc.table("shield_admins").insert({
                        "org_id": org_id, "email": inv_email, "role": inv_role,
                        "invited_by": st.session_state.get("shield_user_email", ""),
                    }).execute()
                    try:
                        svc.auth.admin.invite_user_by_email(inv_email)
                        st.success(f"✅ Invite sent to {inv_email}.")
                    except Exception:
                        st.success(f"✅ Admin record created for {inv_email}. Share the dashboard URL with them.")
                    st.rerun()


# ── Settings ───────────────────────────────────────────────────────────────────
def render_settings(svc: Client, org_id: str):
    org_data = svc.table("shield_organizations").select("*").eq("id", org_id).limit(1).execute().data
    if not org_data:
        st.error("Organization not found.")
        return
    org = org_data[0]

    with st.form("settings"):
        st.text_input("Organization name",     value=org.get("name", ""),             disabled=True)
        st.text_input("Tenant domain",         value=org.get("tenant_domain", ""),    disabled=True)
        st.text_input("Inbound webhook secret", value=org.get("inbound_webhook_secret", ""), disabled=True,
                      help="Use this as the secret in your M365 mail flow rule.")
        it_email      = st.text_input("IT security email", value=org.get("it_security_email", "") or "")
        threshold     = st.selectbox("Quarantine threshold", ["PHISHING", "SUSPICIOUS"],
                                     index=0 if org.get("quarantine_threshold") == "PHISHING" else 1)
        custom_prompt = st.text_area("Custom AI instructions (optional)",
                                     value=org.get("custom_prompt", "") or "",
                                     help="Additional context passed to Claude on every email analysis.")
        if st.form_submit_button("Save settings", type="primary"):
            svc.table("shield_organizations").update({
                "it_security_email":    it_email or None,
                "quarantine_threshold": threshold,
                "custom_prompt":        custom_prompt or None,
                "updated_at":           datetime.now(timezone.utc).isoformat(),
            }).eq("id", org_id).execute()
            st.success("Settings saved.")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    st.set_page_config(
        page_title="Clarivise Shield",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_theme()

    # ── Handle invite / password-reset link ───────────────────────────────────
    # Supabase appends #access_token=...&type=invite to the URL.
    # Streamlit exposes these as query params after the fragment is parsed.
    params = st.query_params
    token_type   = params.get("type", "")
    access_token = params.get("access_token", "")
    refresh_token = params.get("refresh_token", "")

    if token_type in ("invite", "recovery") and access_token:
        render_set_password(access_token, refresh_token or access_token)
        return

    anon = get_anon_client()
    if not anon:
        st.error("Dashboard not configured — SUPABASE_ANON_KEY missing from secrets.")
        return

    user = get_auth_user(anon)
    if not user:
        render_login()
        return

    svc = get_svc_client()
    if not svc:
        st.error("Dashboard not configured — SUPABASE_SERVICE_ROLE_KEY missing from secrets.")
        return

    admin = get_admin_record(svc, str(user.id))
    if not admin:
        st.error("No Shield admin account found for your login. Contact support.")
        if st.button("Sign out"):
            anon.auth.sign_out()
            st.session_state.clear()
            st.rerun()
        return

    is_super   = admin.get("is_super_admin", False)
    user_email = admin.get("email", getattr(user, "email", ""))
    st.session_state["shield_user_email"] = user_email

    if is_super:
        selected_org_id   = st.session_state.get("selected_org_id")
        selected_org_name = st.session_state.get("selected_org_name")
        if selected_org_id:
            render_org_dashboard(svc, selected_org_id, selected_org_name, is_super=True, user_email=user_email)
        else:
            with st.sidebar:
                st.markdown("### 🛡️ Clarivise Shield")
                st.caption("Super Admin")
                st.divider()
                st.caption(f"**{user_email}**")
                if st.button("Sign out"):
                    anon.auth.sign_out()
                    st.session_state.clear()
                    st.rerun()
            render_super_admin(svc)
    else:
        org = admin.get("shield_organizations")
        if not org:
            org_res = svc.table("shield_organizations").select("id, name") \
                .eq("id", admin["org_id"]).limit(1).execute()
            org = org_res.data[0] if org_res.data else None
        if not org:
            st.error("Your account is not linked to an organization. Contact support.")
            return
        render_org_dashboard(svc, org["id"], org["name"], is_super=False, user_email=user_email)


if __name__ == "__main__":
    main()
