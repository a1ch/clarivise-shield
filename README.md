# Clarivise Shield

AI-powered email security for Microsoft 365. Every inbound email is analyzed by Claude after Microsoft's spam filter, and a plain-English risk verdict is stamped onto the message.

## Operating model: marking (non-destructive)

Shield runs in **marking mode**. Mail is delivered to the mailbox normally, then scanned and **tagged** — it is never blocked or held before the inbox. This is deliberate: zero risk of losing legitimate mail, and it works without rewriting Exchange mail flow.

```
Internet -> Microsoft 365 EOP (spam filter) -> Mailbox (delivered)
         -> Shield Connector polls new mail (every 60s, Graph API)
         -> resolve short URLs (no token cost)
         -> Supabase Edge Function (shield-inbound) -> Claude (verdict)
         -> tag subject + inject scan-report banner in body
         -> log result; flagged mail added to the review queue
```

**Verdict actions (marking only):**

| Verdict | Action |
|---|---|
| SAFE | banner only |
| SPAM | `[SPAM]` subject prefix + banner |
| SUSPICIOUS | `[SUSPICIOUS]` subject prefix + banner |
| PHISHING | `[PHISHING]` subject prefix + warning banner + added to review queue |

The dashboard's "review queue" (the `shield_quarantine` table) is a **record of flagged messages for admin review** — it does not hold mail out of the inbox. "Release" / "Delete" there update the review status (and can optionally remove the tagged copy from the mailbox via Graph). True pre-inbox quarantine would require Exchange transport rules and is intentionally out of scope for the marking model.

## Projects

| Directory | Purpose |
|---|---|
| `connector/` | FastAPI poller (Azure Container App) — fetches new mail, calls the pipeline, tags messages |
| `supabase/` | Edge functions (`shield-inbound`, `shield-admin`, `shield-daily-summary`) + DB schema |
| `dashboard/` | Admin dashboard (stats, review queue, allow/block lists, settings) |
| `m365/` | PowerShell setup + test scripts for the M365 app registration |

## Project

- **Supabase project:** `eysvvjrsjbfyeuggyhey`
- **Region:** Canada Central
