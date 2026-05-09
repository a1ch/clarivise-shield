# Clarivise Shield

AI-powered email security pipeline for Microsoft 365. Every inbound email is analyzed by Claude AI after Microsoft's spam filter and before it reaches the user's inbox.

## Architecture

```
Internet -> Microsoft 365 EOP (spam filter) -> Shield Inbound Connector
         -> Supabase Edge Function (analyze)
         -> Claude AI (verdict)
         -> Deliver / Tag / Quarantine
         -> User Inbox
```

## Projects

| Directory | Purpose |
|---|---|
| `supabase/` | Edge functions, DB migrations, config |
| `dashboard/` | Next.js admin dashboard |
| `m365/` | PowerShell setup scripts for M365 connector |
| `docs/` | Architecture, setup, API reference |

## Quick Start

See [docs/SETUP.md](docs/SETUP.md) for full setup instructions.

## Project

- **Supabase project:** `eysvvjrsjbfyeuggyhey`
- **Region:** Canada Central
