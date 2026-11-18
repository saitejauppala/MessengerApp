# MessengerApp

Zero-knowledge, end-to-end encrypted real-time messenger web app.

- **Client:** React 19 + TypeScript + Vite + Tailwind CSS (`src/`)
- **Server:** Node.js + TypeScript microservice (`server/`) for scheduled cleanup and zero-IP-leak link previews, deployable to Render
- **Backend:** Supabase (Auth, PostgreSQL, Realtime, Storage)

## Security model

- End-to-end encryption with the native Web Crypto API only (ECDH P-256 + HKDF-SHA-256 key agreement, AES-GCM encryption with fresh 12-byte IVs, ECDSA-SHA-256 signatures).
- Private keys never leave the client device; they are stored locally (IndexedDB) or in volatile memory ("No Local Cache Mode").
- Every AES-GCM operation uses a cryptographically random 96-bit IV and a 128-bit authentication tag.
- Messages and media are encrypted client-side before being written to Supabase; Supabase never sees plaintext or unencrypted files.
- Strict Row Level Security on every Supabase table.

## Client environment variables

Copy `src/.env.example` to `.env` (not committed):

```
VITE_SUPABASE_URL=your-supabase-project-url
VITE_SUPABASE_ANON_KEY=your-supabase-anon-key
```

## Server (`server/`)

Deployable to Render as a Node.js service. Copy `server/.env.example` to `server/.env`:

```
PORT=3001
SUPABASE_URL=your-supabase-project-url
SUPABASE_SERVICE_ROLE_KEY=your-supabase-service-role-key
CRON_SECRET=your-long-random-cron-secret
ALLOWED_ORIGIN=https://your-messengerapp-domain.com
```

### Scripts

| Script | Purpose |
|--------|---------|
| `npm run build` | Compile TypeScript to `dist/` |
| `npm start` | Run the compiled server (production) |
| `npm run dev` | Run with `ts-node` (development) |
| `npm run typecheck` | Type-check without emitting |

### Endpoints

- `GET /health` — `{ status: "ok", timestamp }` for uptime monitoring.
- `POST /api/cleanup` — Requires `Authorization: Bearer <CRON_SECRET>` (compared with `crypto.timingSafeEqual`). Runs `supabase.rpc('cleanup_expired_messages')` and removes expired/viewed view-once media blobs from Supabase Storage. Call on a schedule (e.g. Render Cron).
- `POST /api/link-preview` — Accepts `{ url }`, validates it is a public HTTPS URL, blocks private/internal SSRF ranges (`127.0.0.1`, `10.0.0.0/8`, `169.254.169.254`, IPv6 link-local/unique-local, etc.), fetches server-side with a 3-second timeout, and returns sanitized `<title>`, `<meta name="description">`, and `og:image`. The server fetches on the client's behalf so client IPs are never exposed to external domains.

### Local testing

```bash
cd server
cp .env.example .env   # fill in real values
npm install
npm run typecheck
npm run dev
# In another terminal:
curl http://localhost:3001/health
```

### Supabase migration setup

Apply `supabase/migrations/001_init_e2ee_schema.sql` to your Supabase project. It creates `profiles`, `user_keys`, `user_privacy_settings`, `contacts`, `blocked_users`, `conversations`, `conversation_members`, `messages`, `message_receipts`, the `handle_new_user` trigger, strict RLS policies, and the `cleanup_expired_messages()` function used by `/api/cleanup`.

The `e2ee-files` Supabase Storage bucket must exist for media uploads/view-once blobs.

## License

Private — not for redistribution.
