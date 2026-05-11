"""
Clarivise Shield Connector
Azure Container App — FastAPI service that:
  1. [Active] Polls the shield-scan mailbox every 60s for unread messages (Option B)
  2. [Ready]  Receives Graph API change notifications via webhook (Option A — future)
  3. Fetches each new email via Graph API
  4. Resolves short URLs to their final destination (zero token cost)
  5. POSTs parsed content to the Shield inbound edge function
  6. Tags the email subject based on verdict (marking mode — no blocking)

Verdict actions (marking only):
  SAFE       → do nothing
  SPAM       → prepend [SPAM] to subject
  SUSPICIOUS → prepend [SUSPICIOUS] to subject
  PHISHING   → prepend [PHISHING] to subject + insert warning banner in body

Polling vs Webhooks:
  Option B (current): On startup, a background task polls MAILBOX for unread
  mail on POLL_INTERVAL_SECONDS cadence. Messages are marked as read after
  processing so they are not re-scanned.

  Option A (future): Graph API push notifications via /webhook/graph. Requires
  a public HTTPS URL and an active subscription. All webhook code below is
  preserved and ready — just register a subscription via /webhook/subscription/create
  and set POLL_INTERVAL_SECONDS=0 to disable polling once webhooks are live.
"""

import asyncio
import hashlib
import hmac
import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

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
TENANT_ID           = os.environ["AZURE_TENANT_ID"]
CLIENT_ID           = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET       = os.environ["AZURE_CLIENT_SECRET"]
MAILBOX             = os.environ["SHIELD_MAILBOX"]
SHIELD_WEBHOOK      = os.environ["SHIELD_INBOUND_URL"]
SHIELD_SECRET       = os.environ["SHIELD_INBOUND_SECRET"]
NOTIFICATION_SECRET = os.environ.get("GRAPH_NOTIFICATION_SECRET", "")
ORG_ID              = os.environ.get("SHIELD_ORG_ID", "f775557a-cbe4-4b77-ab43-b20b9799db3e")
POLL_INTERVAL_SECS  = int(os.environ.get("POLL_INTERVAL_SECONDS", "60"))

GRAPH_BASE     = "https://graph.microsoft.com/v1.0"
TOKEN_URL      = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
MAX_BODY_CHARS = 3000

# ── Known URL shortener domains ────────────────────────────────────────────────
# These are resolved to their final destination before AI analysis.
# Zero token cost — just HTTP HEAD requests to follow redirects.
SHORT_LINK_DOMAINS = {
    # Google
    "c.gle", "goo.gl", "g.co",
    # Generic
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "ow.ly",
    "buff.ly", "dlvr.it", "ift.tt", "tiny.cc", "short.link",
    "rb.gy", "cutt.ly", "bl.ink", "shorte.st", "clck.ru",
    # Microsoft
    "aka.ms", "go.microsoft.com",
    # Email marketing (resolve so AI sees landing page domain)
    "click.em.yourdomain.com", "mailchi.mp", "list-manage.com",
}


# ── Lifespan (startup/shutdown) ────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start background polling loop on startup; cancel on shutdown."""
    poll_task = None
    if POLL_INTERVAL_SECS > 0:
        log.info("Starting mailbox polling loop (interval: %ds)", POLL_INTERVAL_SECS)
        poll_task = asyncio.create_task(mailbox_poll_loop())
    else:
        log.info("Polling disabled (POLL_INTERVAL_SECONDS=0) — webhook-only mode")
    yield
    if poll_task:
        poll_task.cancel()
        try:
            await poll_task
        except asyncio.CancelledError:
            pass
        log.info("Polling loop stopped")

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="Clarivise Shield Connector", version="1.0.0", lifespan=lifespan)

_token_cache: dict = {"token": None, "expires_at": 0.0}
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


# ── URL short-link resolver ────────────────────────────────────────────────────
def is_short_link(url: str) -> bool:
    """Return True if the URL's domain is a known shortener."""
    try:
        domain = urlparse(url).netloc.lower().replace("www.", "")
        return domain in SHORT_LINK_DOMAINS
    except Exception:
        return False


async def resolve_url(url: str, timeout: float = 5.0) -> str:
    """
    Follow redirects on a URL and return the final destination.
    Uses HEAD to avoid downloading response bodies.
    Falls back to the original URL on any error.
    """
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": "Clarivise-Shield/1.0 (link-resolver)"},
        ) as client:
            res = await client.head(url)
            final = str(res.url)
            if final != url:
                log.info("Resolved short link: %s → %s", url, final)
            return final
    except Exception as ex:
        log.debug("Could not resolve %s: %s", url, ex)
        return url


async def resolve_short_links(links: list[dict]) -> list[dict]:
    """
    For any link whose domain is a known shortener, resolve it to its
    final destination and update both fullUrl and href (domain).
    Runs all resolutions concurrently — typically adds <200ms total.
    """
    async def resolve_one(link: dict) -> dict:
        url = link.get("fullUrl", "")
        if not url or not is_short_link(url):
            return link
        resolved = await resolve_url(url)
        if resolved != url:
            try:
                resolved_domain = urlparse(resolved).netloc.lower().replace("www.", "")
                return {**link, "fullUrl": resolved, "href": resolved_domain, "shortLinkResolved": True, "originalUrl": url}
            except Exception:
                pass
        return link

    return list(await asyncio.gather(*[resolve_one(l) for l in links]))


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
                "Content-Type":    "application/json",
                "x-shield-secret": SHIELD_SECRET,
                "x-org-id":        ORG_ID,
            },
            json=email_data,
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
  {summary}
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

    try:
        msg = await graph_get(client, f"/users/{MAILBOX}/messages/{message_id}?$select=subject,body")
        current_subject = msg.get("subject", "")

        if not current_subject.startswith(prefix):
            updates["subject"] = prefix + current_subject

        if verdict == "PHISHING":
            body_obj     = msg.get("body", {})
            body_content = body_obj.get("content", "")
            body_type    = body_obj.get("contentType", "text")

            if body_type == "html":
                banner = WARNING_BANNER.format(
                    verdict=verdict,
                    summary=result.get("summary", "")[:200],
                )
                updates["body"] = {
                    "contentType": "html",
                    "content":     banner + body_content,
                }
            else:
                warning = f"\n\n⚠️ CLARIVISE SHIELD WARNING: This email was flagged as PHISHING. {result.get('summary', '')}\n\n"
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

    if len(_processed) > 5000:
        oldest = list(_processed)[:1000]
        for m in oldest:
            _processed.discard(m)

    async with httpx.AsyncClient() as client:
        try:
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

        # Resolve short links — zero token cost, runs concurrently
        short_links = [l for l in email_data["links"] if is_short_link(l.get("fullUrl", ""))]
        if short_links:
            log.info("Resolving %d short link(s) in message %s", len(short_links), message_id)
            email_data["links"] = await resolve_short_links(email_data["links"])

        log.info("Processing: [%s] from %s", email_data["subject"][:60], email_data["sender"][:60])

        result = await analyze_with_shield(client, email_data)
        if not result:
            log.warning("No Shield result for %s — skipping tag", message_id)
            return

        verdict = result.get("verdict", "SAFE")
        action  = result.get("action", "delivered")
        summary = result.get("summary", "")

        log.info("Verdict: %s | Action: %s | %s", verdict, action, summary[:80])

        await tag_email(client, message_id, verdict, result)

        try:
            await graph_patch(client, f"/users/{MAILBOX}/messages/{message_id}", {"isRead": True})
        except Exception as ex:
            log.warning("Could not mark message %s as read: %s", message_id, ex)


# ── Option B: Mailbox polling loop ─────────────────────────────────────────────
async def poll_mailbox_once():
    """
    Fetch all unread messages from the shared mailbox and enqueue them for processing.
    Messages are marked as read inside process_message() after a successful scan,
    so they won't be picked up on the next poll.
    """
    async with httpx.AsyncClient() as client:
        try:
            data = await graph_get(
                client,
                f"/users/{MAILBOX}/messages"
                "?$filter=isRead eq false"
                "&$select=id,subject,from,receivedDateTime"
                "&$orderby=receivedDateTime asc"
                "&$top=50",
            )
        except Exception as ex:
            log.error("Poll: failed to list mailbox messages: %s", ex)
            return

        messages = data.get("value", [])
        if not messages:
            log.debug("Poll: no unread messages")
            return

        log.info("Poll: found %d unread message(s)", len(messages))
        for msg in messages:
            message_id = msg.get("id")
            subject    = msg.get("subject", "")[:60]
            if message_id and message_id not in _processed:
                log.info("Poll: queuing message [%s]", subject)
                asyncio.create_task(process_message(message_id))


async def mailbox_poll_loop():
    """
    Background loop: poll the shared mailbox on a fixed interval.
    Runs until cancelled (on app shutdown).

    To migrate to Option A (Graph API webhooks):
      1. Register a subscription via POST /webhook/subscription/create
      2. Set POLL_INTERVAL_SECONDS=0 in your container env vars
      3. The webhook endpoint at /webhook/graph takes over
    """
    await asyncio.sleep(5)
    log.info("Poll loop started — interval %ds, mailbox: %s", POLL_INTERVAL_SECS, MAILBOX)
    while True:
        try:
            await poll_mailbox_once()
        except asyncio.CancelledError:
            raise
        except Exception as ex:
            log.error("Poll loop unexpected error: %s", ex)
        await asyncio.sleep(POLL_INTERVAL_SECS)


# ── Health & admin endpoints ───────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status":        "ok",
        "service":       "clarivise-shield-connector",
        "polling":       POLL_INTERVAL_SECS > 0,
        "poll_interval": POLL_INTERVAL_SECS,
        "processed":     len(_processed),
    }


@app.post("/webhook/reprocess/{message_id}")
async def reprocess(message_id: str, background_tasks: BackgroundTasks):
    """Manually reprocess a specific message — useful for testing."""
    _processed.discard(message_id)
    background_tasks.add_task(process_message, message_id)
    return {"queued": message_id}


@app.post("/poll/now")
async def poll_now():
    """Trigger an immediate poll of the mailbox — useful for testing without waiting."""
    asyncio.create_task(poll_mailbox_once())
    return {"status": "poll triggered"}


# ── Option A: Graph API webhook endpoints (ready for future use) ───────────────
@app.post("/webhook/graph")
async def graph_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Receives Graph API change notifications (Option A — future).
    Graph sends a validationToken on first subscription — must echo it back.
    Subsequent POSTs are actual notifications.
    Enable by registering a subscription via /webhook/subscription/create
    and setting POLL_INTERVAL_SECONDS=0 to disable polling.
    """
    validation_token = request.query_params.get("validationToken")
    if validation_token:
        log.info("Graph subscription validation handshake")
        return PlainTextResponse(validation_token, status_code=200)

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

    return Response(status_code=202)


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
    """
    Create or renew the Graph API webhook subscription (Option A — future).
    Once created, set POLL_INTERVAL_SECONDS=0 to switch from polling to push.
    """
    body = await request.json()
    notification_url = body.get("notification_url")

    if not notification_url:
        raise HTTPException(status_code=400, detail="notification_url required")

    from datetime import timedelta
    expiry = (datetime.now(timezone.utc) + timedelta(hours=4230)).strftime("%Y-%m-%dT%H:%M:%SZ")

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
