# Hound Operator Dashboard

A private, single-file HTML dashboard for monitoring all Hound agents in the field.

## What it shows

- **Fleet stats** — total agents, active last 24h, online now (last 5 min), threats detected
- **Mode breakdown** — how many agents are in simulation vs. live response mode
- **Version distribution** — agent version spread across active fleet
- **Agent table** — most recent heartbeat per agent: ID, macOS version, agent version, last seen, online status, mode, threat count

## Setup

### 1. Run the Supabase migration

Apply `supabase/migrations/001_create_heartbeats.sql` to your Supabase project:

```bash
supabase db push
# or paste the SQL directly in the Supabase dashboard → SQL editor
```

### 2. Deploy the Edge Function

```bash
supabase functions deploy heartbeat
```

### 3. Set the dashboard password

Edit `apps/operator-dashboard/index.html`, find this line near the top of the `<script>` block:

```js
const DASHBOARD_PW = "hound-operator-2026";
```

Change it to a strong password. This password is stored only in your browser's `sessionStorage` for the current tab session.

### 4. Open the dashboard

Just open the file in a browser — no server required:

```bash
open apps/operator-dashboard/index.html
```

Or serve it locally:

```bash
cd apps/operator-dashboard
python3 -m http.server 8080
# then open http://localhost:8080
```

## Data flow

```
Hound agent (Tauri desktop app)
  → POST /functions/v1/heartbeat  (every 5 minutes)
  → Supabase heartbeats table
  → Operator dashboard reads via anon key (read-only)
```

The anon key is hardcoded in the HTML. Supabase row-level security is **not** enabled on the heartbeats table by default — this dashboard is intended for local/private use only. Do not expose this file on a public server.

## Refresh behavior

- Auto-refreshes every 60 seconds
- "Last synced: Xs ago" counter in the top bar
- Manual refresh button available

## Security notes

- The password gate uses `sessionStorage` — it resets when the tab is closed
- The Supabase anon key is read-only by default (no write access from the dashboard)
- All agent data is pseudonymous (UUID agent IDs, no user PII beyond what's in heartbeats)
- For team use, host behind a VPN or basic auth proxy rather than exposing publicly
