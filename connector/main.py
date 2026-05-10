"""
Clarivise Shield Connector
Azure Container App — FastAPI service that:
  1. Receives Graph API change notifications for the shield-scan mailbox
  2. Fetches each new email via Graph API
  3. POSTs parsed content to the Shield inbound edge function
  4. Tags the email subject based on verdict (marking mode — no blocking)

Verdict actions (marking only):
  SAFE       → do nothing
  SPAM       → prepend [SPAM] to subject
  SUSPICIOUS → prepend [SUSPICIOUS] to subject
  PHISHING   → prepend [PHISHING] to subject + insert warning banner in body
"""

import asyncio
import hashlib
import hmac
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("shield-connector")

# ── Config ─────────────────────────────────────────────────────────────────────
TENANT_ID         = os.environ["AZURE_TENANT_ID"]
CLIENT_ID         = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET     = os.environ["AZURE_CLIENT_SECRET"]
MAILBOX           = os.environ["SHIELD_MAILBOX"]          # shield-scan@ingotsolutions.com
SHIELD_WEBHOOK    = os.environ["SHIELD_INBOUND_URL"]      # https://eysvvjrsjbfyeuggyhey.supabase.co/functions/v1/shield-inbound
SHIELD_SECRET     = os.environ["SHIELD_INBOUND_SECRET"]   # clarivise-shield-ee47a2b9-...
NOTIFICATION_SECRET = os.environ.get("GRAPH_NOTIFICATION_SECRET", "")
ORG_ID            = os.environ.get("SHIELD_ORG_ID", "f775557a-cbe4-4b77-ab43-b20b9799db3e")

GRAPH_BASE        = "https://graph.microsoft.com/v1.0"
TOKEN_URL         = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
MAX_BODY_CHARS    = 3000

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="Clarivise Shield Connector", version="1.0.0")

# In-memory token cache
_token_cache: dict = {"token": None, "expires_at": 0.0}
# Track processed message IDs to avoid double-processing
_processed: set = set()


# ── Microsoft Graph Auth ───────────────────────────────────────────────────────
async def get_graph_token(client: httpx.AsyncClient) -> str:
    now = datetime.now(timezone.utc).timestamp()
    if _token_cache["token"] and _token_cache["expires_at"] > now + 60:
        return _token_cache["token"]

    res = await client.post(TOKEN_URL, data={
        "grant_type":    "client_credentials",
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope":         "https://graph.microsoft.com/.default",
    })
    res.raise_for_status()
    data = res.json()
    _token_cache["token"]      = data["access_token"]
    _token_cache["expires_at"] = now + data["expires_in"]
    return _token_cache["token"]


async def graph_get(client: httpx.AsyncClient, path: str) -> dict:
    token = await get_graph_token(client)
    res   = await client.get(
        f"{GRAPH_BASE}{path}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    res.raise_for_status()
    return res.json()


async def graph_patch(client: httpx.AsyncClient, path: str, body: dict) -> dict:
    token = await get_graph_token(client)
    res   = await client.patch(
        f"{GRAPH_BASE}{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=body,
        timeout=30,
    )
    res.raise_for_status()
    return res.json()


# ── Email parsing ──────────────────────────────────────────────────────────────
def extract_links(body_html: str, body_text: str) -> list[dict]:
    """Extract links from email body HTML."""
    links = []
    seen  = set()
    for match in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', body_html or "", re.IGNORECASE | re.DOTALL):
        href    = match.group(1).strip()
        display = re.sub(r"<[^>]+>", "", match.group(2)).strip()[:200]
        if href and href not in seen and not href.startswith("mailto:"):
            seen.add(href)
            try:
                from urllib.parse import urlparse
                parsed = urlparse(href)
                domain = parsed.netloc.lower().replace("www.", "")
                links.append({"display": display or domain, "href": domain, "fullUrl": href})
            except Exception:
                pass
    return links[:20]


def parse_message(msg: dict) -> dict:
    """Convert a Graph API message object into Shield's expected format."""
    subject     = msg.get("subject", "") or ""
    sender_obj  = msg.get("from", {}).get("emailAddress", {})
    sender_name = sender_obj.get("name", "")
    sender_addr = sender_obj.get("address", "")
    sender      = f"{sender_name} <{sender_addr}>" if sender_name else sender_addr

    to_list     = msg.get("toRecipients", [])
    recipient   = to_list[0]["emailAddress"]["address"] if to_list else ""

    body_obj    = msg.get("body", {})
    body_html   = body_obj.get("content", "") if body_obj.get("contentType") == "html" else ""
    body_text   = re.sub(r"<[^>]+>", " ", body_html) if body_html else body_obj.get("content", "")
    body_clean  = re.sub(r"\s+", " ", body_text).strip()[:MAX_BODY_CHARS]

    attachments = [
        a.get("name", "")
        for a in msg.get("attachments", [])
        if a.get("name")
    ]

    reply_to_list = msg.get("replyTo", [])
    reply_to      = reply_to_list[0]["emailAddress"]["address"] if reply_to_list else None

    links = extract_links(body_html, body_clean)

    # Check if sender is external (not in our org)
    is_external = sender_addr.lower().split("@")[-1] if "@" in sender_addr else ""

    return {
        "subject":        subject,
        "sender":         sender,
        "recipient":      recipient,
        "senderHasEmail": bool(sender_addr),
        "body":           body_clean,
        "links":          links,
        "attachments":    attachments,
        "hasHighRiskAttachment":    False,
        "hasSuspiciousAttachment":  False,
        "highRiskFiles":            [],
        "suspiciousFiles":          [],
        "isOutlookExternal":        True,
        "clientTimestamp":          msg.get("receivedDateTime", datetime.now(timezone.utc).isoformat()),
        "clientTimezone":           "America/Edmonton",
        "replyTo":                  reply_to,
        "senderEmail":              sender_addr,
        "displayName":              sender_name,
    }


# ── Shield analysis ────────────────────────────────────────────────────────────
async def analyze_with_shield(client: httpx.AsyncClient, email_data: dict) -> Optional[dict]:
    """POST email data to the Shield inbound edge function."""
    try:
        res = await client.post(
            SHIELD_WEBHOOK,
            headers={
                "Content-Type":      "application/json",
                "x-shield-secret":   SHIELD_SECRET,
                "x-org-id":          ORG_ID,
            },
            json={"emailData": email_data, "tenantDomain": "ingotsolutions.com"},
            timeout=30,
        )
        if res.status_code == 200:
            return res.json()
        log.warning("Shield returned %d: %s", res.status_code, res.text[:200])
    except Exception as ex:
        log.error("Shield call failed: %s", ex)
    return None


# ── Email tagging ──────────────────────────────────────────────────────────────
WARNING_BANNER = """
<div style="background:#fff3cd;border:2px solid #ffc107;border-radius:6px;padding:12px 16px;margin:0 0 16px;font-family:Arial,sans-serif;font-size:13px;color:#856404;">
  <strong>⚠️ Clarivise Shield Warning</strong><br>
  This email has been flagged as <strong>{verdict}</strong> by Clarivise Shield AI.
  Phishing score: {score}/100. {summary}
  <br><em>Do not click links or open attachments unless you are certain of the sender's identity.</em>
</div>
"""

SUBJECT_PREFIXES = {
    "SPAM":       "[SPAM] ",
    "SUSPICIOUS": "[SUSPICIOUS] ",
    "PHISHING":   "[PHISHING] ",
}


async def tag_email(client: httpx.AsyncClient, message_id: str, verdict: str, result: dict):
    """Modify the email subject and optionally body to reflect the Shield verdict."""
    if verdict == "SAFE":
        log.info("SAFE — no tagging needed for %s", message_id)
        return

    prefix  = SUBJECT_PREFIXES.get(verdict, "")
    updates = {}

    # Fetch current subject to avoid double-tagging
    try:
        msg = await graph_get(client, f"/users/{MAILBOX}/messages/{message_id}?$select=subject,body")
        current_subject = msg.get("subject", "")

        if not current_subject.startswith(prefix):
            updates["subject"] = prefix + current_subject

        # For phishing, insert a warning banner at the top of the body
        if verdict == "PHISHING":
            body_obj     = msg.get("body", {})
            body_content = body_obj.get("content", "")
            body_type    = body_obj.get("contentType", "text")

            if body_type == "html":
                banner  = WARNING_BANNER.format(
                    verdict=verdict,
                    score=result.get("phishing_score", "?"),
                    summary=result.get("summary", "")[:200],
                )
                updates["body"] = {
                    "contentType": "html",
                    "content":     banner + body_content,
                }
            else:
                warning = f"\n\n⚠️ CLARIVISE SHIELD WARNING: This email was flagged as PHISHING (score: {result.get('phishing_score','?')}/100). {result.get('summary','')}\n\n"
                updates["body"] = {
                    "contentType": "text",
                    "content":     warning + body_content,
                }

        if updates:
            await graph_patch(client, f"/users/{MAILBOX}/messages/{message_id}", updates)
            log.info("Tagged message %s as %s", message_id, verdict)

    except Exception as ex:
        log.error("Failed to tag message %s: %s", message_id, ex)


# ── Core processing ────────────────────────────────────────────────────────────
async def process_message(message_id: str):
    """Fetch, analyze, and tag a single email message."""
    if message_id in _processed:
        log.debug("Already processed %s — skipping", message_id)
        return
    _processed.add(message_id)

    # Keep processed set bounded
    if len(_processed) > 5000:
        oldest = list(_processed)[:1000]
        for m in oldest:
            _processed.discard(m)

    async with httpx.AsyncClient() as client:
        try:
            # Fetch full message
            msg = await graph_get(
                client,
                f"/users/{MAILBOX}/messages/{message_id}"
                "?$select=id,subject,from,toRecipients,body,replyTo,receivedDateTime,attachments"
                "&$expand=attachments($select=name,contentType)",
            )
        except Exception as ex:
            log.error("Failed to fetch message %s: %s", message_id, ex)
            _processed.discard(message_id)
            return

        email_data = parse_message(msg)
        log.info("Processing: [%s] from %s", email_data["subject"][:60], email_data["sender"][:60])

        result = await analyze_with_shield(client, email_data)
        if not result:
            log.warning("No Shield result for %s — skipping tag", message_id)
            return

        # Shield wraps result in a "result" key
        analysis = result.get("result", result)
        verdict  = analysis.get("verdict", "SAFE")
        score    = analysis.get("phishing_score", 0)

        log.info("Verdict: %s (phishing=%s) for message %s", verdict, score, message_id)

        await tag_email(client, message_id, verdict, analysis)


# ── Graph API webhook endpoints ────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "service": "clarivise-shield-connector"}


@app.post("/webhook/graph")
async def graph_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Receives Graph API change notifications.
    Graph sends a validationToken on first subscription — must echo it back.
    Subsequent POSTs are actual notifications.
    """
    # Subscription validation handshake
    validation_token = request.query_params.get("validationToken")
    if validation_token:
        log.info("Graph subscription validation handshake")
        return PlainTextResponse(validation_token, status_code=200)

    # Validate notification secret if configured
    if NOTIFICATION_SECRET:
        client_state = ""
        try:
            body = await request.json()
            notifications = body.get("value", [])
            if notifications:
                client_state = notifications[0].get("clientState", "")
        except Exception:
            pass
        if client_state != NOTIFICATION_SECRET:
            log.warning("Invalid clientState in webhook notification")
            raise HTTPException(status_code=401, detail="Invalid client state")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    notifications = body.get("value", [])
    log.info("Received %d Graph notification(s)", len(notifications))

    for notification in notifications:
        resource_data = notification.get("resourceData", {})
        message_id    = resource_data.get("id")
        change_type   = notification.get("changeType", "")

        if change_type == "created" and message_id:
            log.info("New message notification: %s", message_id)
            background_tasks.add_task(process_message, message_id)

    # Must return 202 quickly — processing happens in background
    return Response(status_code=202)


@app.post("/webhook/reprocess/{message_id}")
async def reprocess(message_id: str, background_tasks: BackgroundTasks):
    """Manually reprocess a specific message — useful for testing."""
    _processed.discard(message_id)
    background_tasks.add_task(process_message, message_id)
    return {"queued": message_id}


@app.get("/webhook/subscription")
async def get_subscription_status():
    """Check current Graph API subscriptions."""
    async with httpx.AsyncClient() as client:
        try:
            data = await graph_get(client, "/subscriptions")
            return {"subscriptions": data.get("value", [])}
        except Exception as ex:
            return {"error": str(ex)}


@app.post("/webhook/subscription/create")
async def create_subscription(request: Request):
    """Create or renew the Graph API webhook subscription."""
    body = await request.json()
    notification_url = body.get("notification_url")  # public HTTPS URL of this container

    if not notification_url:
        raise HTTPException(status_code=400, detail="notification_url required")

    from datetime import timedelta
    expiry = (datetime.now(timezone.utc) + timedelta(hours=4230)).strftime("%Y-%m-%dT%H:%M:%SZ")  # max ~179 days

    subscription_body = {
        "changeType":         "created",
        "notificationUrl":    f"{notification_url}/webhook/graph",
        "resource":           f"/users/{MAILBOX}/messages",
        "expirationDateTime": expiry,
        "clientState":        NOTIFICATION_SECRET or "clarivise-shield",
    }

    async with httpx.AsyncClient() as client:
        token = await get_graph_token(client)
        res = await client.post(
            f"{GRAPH_BASE}/subscriptions",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=subscription_body,
            timeout=30,
        )
        if res.status_code in (200, 201):
            data = res.json()
            log.info("Subscription created: %s expires %s", data.get("id"), data.get("expirationDateTime"))
            return {"subscription": data}
        else:
            log.error("Subscription creation failed: %d %s", res.status_code, res.text)
            raise HTTPException(status_code=res.status_code, detail=res.text)
