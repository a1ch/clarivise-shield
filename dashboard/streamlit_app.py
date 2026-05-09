"""
Clarivise Shield — Admin Dashboard
Streamlit app for viewing scan logs, managing quarantine, and configuring allow/blocklists.
"""
import os
import requests
import streamlit as st
from datetime import datetime

# ── Config ─────────────────────────────────────────────────────────────────────
def _secret(name: str) -> str:
    try:
        v = st.secrets.get(name, "")
    except Exception:
        v = ""
    if v and str(v).strip():
        return str(v).strip()
    return (os.environ.get(name) or "").strip()

SUPABASE_URL = _secret("SUPABASE_URL") or "https://eysvvjrsjbfyeuggyhey.supabase.co"
ADMIN_API    = f"{SUPABASE_URL}/functions/v1/shield-admin"


def api(path: str, token: str, method: str = "GET", body: dict = None):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    res = requests.request(method, ADMIN_API + path, headers=headers, json=body, timeout=15)
    return res.json()


# ── Theme ──────────────────────────────────────────────────────────────────────
def inject_theme():
    st.markdown("""
<style>
    :root { --ink:#0f172a; --muted:#64748b; --accent:#2E75B6; --surface:#fff; --border:#e2e8f0; }
    .block-container { padding-top:0.5rem !important; max-width:1200px; }
    [data-testid="stAppViewContainer"] { background:#0f1f33; }
    [data-testid="stMainBlockContainer"] { color:#e2e8f0; }
    section.main label, section.main [data-testid="stWidgetLabel"] p { color:#94a3b8 !important; }
    section.main [data-testid="stCaption"] { color:#64748b !important; }
    section.main [data-baseweb="input"] input { color:#e2e8f0 !important; -webkit-text-fill-color:#e2e8f0 !important; background:#1a3050 !important; }
    /* Stat cards */
    .stat-card { background:#1a3050; border:1px solid rgba(46,117,182,.25); border-radius:12px; padding:1.25rem; text-align:center; }
    .stat-card .val { font-size:2rem; font-weight:700; line-height:1; margin-bottom:.25rem; }
    .stat-card .lbl { font-size:.75rem; color:#94a3b8; text-transform:uppercase; letter-spacing:.06em; }
    /* Verdict badges */
    .badge-safe { background:#064e3b; color:#6ee7b7; border-radius:6px; padding:.2rem .6rem; font-size:.75rem; font-weight:700; }
    .badge-spam { background:#78350f; color:#fcd34d; border-radius:6px; padding:.2rem .6rem; font-size:.75rem; font-weight:700; }
    .badge-suspicious { background:#7c2d12; color:#fdba74; border-radius:6px; padding:.2rem .6rem; font-size:.75rem; font-weight:700; }
    .badge-phishing { background:#7f1d1d; color:#fca5a5; border-radius:6px; padding:.2rem .6rem; font-size:.75rem; font-weight:700; }
    /* Scan rows */
    .scan-row { background:#1a3050; border:1px solid rgba(46,117,182,.2); border-radius:10px; padding:.85rem 1rem; margin-bottom:.5rem; }
    .scan-row .subject { font-size:.9rem; font-weight:600; color:#e2e8f0; }
    .scan-row .sender { font-size:.78rem; color:#94a3b8; margin-top:.15rem; }
    .scan-row .summary { font-size:.78rem; color:#64748b; margin-top:.3rem; }
    /* Quarantine rows */
    .q-row { background:#1a1a2e; border:1px solid rgba(220,38,38,.3); border-radius:12px; padding:1rem 1.25rem; margin-bottom:.75rem; }
    .q-row .q-subject { font-size:.92rem; font-weight:600; color:#e2e8f0; }
    .q-row .q-sender { font-size:.78rem; color:#94a3b8; margin-top:.2rem; }
    .q-row .q-summary { font-size:.78rem; color:#6b7280; margin-top:.4rem; }
</style>""", unsafe_allow_html=True)


def verdict_badge(v: str) -> str:
    cls = {"SAFE": "safe", "SPAM": "spam", "SUSPICIOUS": "suspicious", "PHISHING": "phishing"}.get(v, "safe")
    return f'<span class="badge-{cls}">{v}</span>'


def fmt_time(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%b %d %H:%M")
    except Exception:
        return ts[:16] if ts else ""


# ── Login ──────────────────────────────────────────────────────────────────────
def render_login():
    st.markdown("""
<div style="max-width:400px;margin:4rem auto;background:#1a3050;border:1px solid rgba(46,117,182,.3);border-radius:16px;padding:2.5rem;">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:1.5rem;">
    <span style="font-size:1.75rem;">🛡️</span>
    <div>
      <div style="font-size:1.1rem;font-weight:700;color:#fff;">Clarivise Shield</div>
      <div style="font-size:.8rem;color:#94a3b8;">Admin Dashboard</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    with st.form("login"):
        email = st.text_input("Admin email", placeholder="admin@yourcompany.com")
        submitted = st.form_submit_button("Sign In", use_container_width=True, type="primary")

    if submitted and email:
        with st.spinner("Signing in..."):
            try:
                data = api("/stats", email.strip())
                if "total_scanned" in data:
                    st.session_state["shield_token"] = email.strip()
                    st.session_state["shield_stats"] = data
                    st.rerun()
                else:
                    st.error("Invalid credentials or no access.")
            except Exception as e:
                st.error(f"Connection error: {e}")


# ── Overview ───────────────────────────────────────────────────────────────────
def render_overview(token: str):
    data = st.session_state.get("shield_stats") or api("/stats", token)
    st.session_state["shield_stats"] = data

    verdicts = data.get("verdicts", {})
    total    = data.get("total_scanned", 0)

    c1, c2, c3, c4 = st.columns(4)
    cards = [
        (c1, str(total),                          "#2E75B6", "Emails Scanned"),
        (c2, str(data.get("quarantine_pending", 0)), "#dc2626", "Quarantine Pending"),
        (c3, f"{data.get('threat_rate', 0)}%",    "#d97706", "Threat Rate"),
        (c4, str(verdicts.get("PHISHING", 0)),    "#dc2626", "Phishing Caught"),
    ]
    for col, val, color, label in cards:
        with col:
            st.markdown(f'<div class="stat-card"><div class="val" style="color:{color};">{val}</div><div class="lbl">{label}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("**Verdict breakdown — last 30 days**")
    v2, v3, v4, v5 = st.columns(4)
    vmap = [
        (v2, "SAFE",       "#059669", verdicts.get("SAFE", 0)),
        (v3, "SPAM",       "#d97706", verdicts.get("SPAM", 0)),
        (v4, "SUSPICIOUS", "#ea580c", verdicts.get("SUSPICIOUS", 0)),
        (v5, "PHISHING",   "#dc2626", verdicts.get("PHISHING", 0)),
    ]
    for col, label, color, count in vmap:
        pct = round((count / total) * 100) if total else 0
        with col:
            st.markdown(f'<div class="stat-card"><div class="val" style="color:{color};">{count}</div><div class="lbl">{label} · {pct}%</div></div>', unsafe_allow_html=True)

    if st.button("🔄 Refresh", key="refresh_overview"):
        st.session_state.pop("shield_stats", None)
        st.rerun()


# ── Scan Log ───────────────────────────────────────────────────────────────────
def render_scans(token: str):
    col1, col2 = st.columns([3, 1])
    with col2:
        filter_verdict = st.selectbox("Filter", ["All", "PHISHING", "SUSPICIOUS", "SPAM", "SAFE"], key="scan_filter")

    path = "/scans?limit=100"
    if filter_verdict != "All":
        path += f"&verdict={filter_verdict}"

    with st.spinner("Loading..."):
        data = api(path, token)

    scans = data.get("scans", [])
    st.caption(f"{len(scans)} emails")

    for s in scans:
        badge = verdict_badge(s.get("verdict", "SAFE"))
        st.markdown(f"""
<div class="scan-row">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;">
    <div style="flex:1;min-width:0;">
      {badge}
      <span class="subject" style="margin-left:.5rem;">{s.get('subject', '(no subject)')}</span>
      <div class="sender">{s.get('sender', '')}</div>
      <div class="summary">{s.get('summary', '')}</div>
    </div>
    <div style="text-align:right;flex-shrink:0;margin-left:1rem;">
      <div style="font-size:.75rem;color:#64748b;">{fmt_time(s.get('created_at', ''))}</div>
      <div style="font-size:.72rem;color:#475569;margin-top:.2rem;">{s.get('actioned', 'delivered')}</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    if not scans:
        st.info("No scans yet.")


# ── Quarantine ─────────────────────────────────────────────────────────────────
def render_quarantine(token: str):
    with st.spinner("Loading quarantine..."):
        data = api("/quarantine", token)

    items = data.get("quarantine", [])
    st.caption(f"{len(items)} pending")

    for item in items:
        st.markdown(f"""
<div class="q-row">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;">
    <div style="flex:1;min-width:0;">
      <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.3rem;">
        {verdict_badge(item.get('verdict','PHISHING'))}
        <span style="font-size:.75rem;color:#6b7280;">{fmt_time(item.get('created_at',''))}</span>
      </div>
      <div class="q-subject">{item.get('subject','(no subject)')}</div>
      <div class="q-sender">{item.get('sender','')}</div>
      <div class="q-summary">{item.get('summary','')}</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

        col1, col2, col3 = st.columns([2, 1, 1])
        with col2:
            if st.button("✅ Release", key=f"rel_{item['id']}", use_container_width=True):
                api(f"/quarantine/{item['id']}/release", token, "POST", {"notes": "Released by admin"})
                st.success("Released")
                st.rerun()
        with col3:
            if st.button("🗑️ Delete", key=f"del_{item['id']}", use_container_width=True):
                api(f"/quarantine/{item['id']}/delete", token, "POST")
                st.success("Deleted")
                st.rerun()

    if not items:
        st.success("✅ Quarantine is empty.")


# ── Allow/Block Lists ──────────────────────────────────────────────────────────
def render_lists(token: str):
    tab1, tab2 = st.tabs(["✅ Allowlist", "🚫 Blocklist"])

    with tab1:
        data = api("/allowlist", token)
        items = data.get("allowlist", [])
        for item in items:
            c1, c2 = st.columns([5, 1])
            with c1:
                st.markdown(f"**{item['value']}** `{item['type']}` — {item.get('note','')}")
            with c2:
                if st.button("Remove", key=f"allow_del_{item['id']}"):
                    api(f"/allowlist/{item['id']}", token, "DELETE")
                    st.rerun()
        st.divider()
        st.markdown("**Add to allowlist**")
        with st.form("add_allow"):
            a1, a2 = st.columns(2)
            with a1:
                val = st.text_input("Email or domain", placeholder="sender@example.com or example.com")
            with a2:
                typ = st.selectbox("Type", ["email", "domain"])
            note = st.text_input("Note (optional)")
            if st.form_submit_button("Add"):
                api("/allowlist", token, "POST", {"type": typ, "value": val, "note": note})
                st.success(f"Added {val} to allowlist")
                st.rerun()

    with tab2:
        data = api("/blocklist", token)
        items = data.get("blocklist", [])
        for item in items:
            c1, c2 = st.columns([5, 1])
            with c1:
                st.markdown(f"**{item['value']}** `{item['type']}` — {item.get('note','')}")
            with c2:
                if st.button("Remove", key=f"block_del_{item['id']}"):
                    api(f"/blocklist/{item['id']}", token, "DELETE")
                    st.rerun()
        st.divider()
        st.markdown("**Add to blocklist**")
        with st.form("add_block"):
            b1, b2 = st.columns(2)
            with b1:
                val = st.text_input("Email or domain", placeholder="spammer@evil.com or evil.com")
            with b2:
                typ = st.selectbox("Type", ["email", "domain"], key="block_type")
            note = st.text_input("Note (optional)", key="block_note")
            if st.form_submit_button("Add"):
                api("/blocklist", token, "POST", {"type": typ, "value": val, "note": note})
                st.success(f"Added {val} to blocklist")
                st.rerun()


# ── Settings ───────────────────────────────────────────────────────────────────
def render_settings(token: str):
    data = api("/settings", token)

    with st.form("settings"):
        st.text_input("Organization name", value=data.get("name", ""), disabled=True)
        st.text_input("Tenant domain", value=data.get("tenant_domain", ""), disabled=True)
        it_email    = st.text_input("IT security email", value=data.get("it_security_email", ""))
        threshold   = st.selectbox("Quarantine threshold", ["PHISHING", "SUSPICIOUS"],
                                   index=0 if data.get("quarantine_threshold") == "PHISHING" else 1)
        custom_prompt = st.text_area("Custom AI instructions (optional)",
                                     value=data.get("custom_prompt", "") or "",
                                     help="Additional instructions passed to Claude on every email analysis.")
        if st.form_submit_button("Save settings", type="primary"):
            api("/settings", token, "PUT", {
                "it_security_email":    it_email,
                "quarantine_threshold": threshold,
                "custom_prompt":        custom_prompt or None,
            })
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

    token = st.session_state.get("shield_token")

    if not token:
        render_login()
        return

    # Sidebar
    with st.sidebar:
        st.markdown("### 🛡️ Clarivise Shield")
        st.caption("Admin Dashboard")
        st.divider()
        tab = st.radio("Navigate", ["Overview", "Scan Log", "Quarantine", "Allow/Block", "Settings"],
                       label_visibility="collapsed")
        st.divider()
        st.caption(f"Signed in as **{token}**")
        if st.button("Sign out"):
            st.session_state.clear()
            st.rerun()

    # Header
    titles = {
        "Overview":   ("📊 Overview", "Last 30 days"),
        "Scan Log":   ("📋 Scan Log", "All analyzed emails"),
        "Quarantine": ("🔒 Quarantine", "Emails pending review"),
        "Allow/Block":("✅🚫 Allow/Block Lists", "Trusted and blocked senders"),
        "Settings":   ("⚙️ Settings", "Organization configuration"),
    }
    title, subtitle = titles.get(tab, ("Shield", ""))
    st.markdown(f"## {title}")
    st.caption(subtitle)
    st.divider()

    if tab == "Overview":
        render_overview(token)
    elif tab == "Scan Log":
        render_scans(token)
    elif tab == "Quarantine":
        render_quarantine(token)
    elif tab == "Allow/Block":
        render_lists(token)
    elif tab == "Settings":
        render_settings(token)


if __name__ == "__main__":
    main()
