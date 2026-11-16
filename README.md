# Vaani Worker

Same-origin API for Vaani authentication and developer bot controls.

## API routes

- `GET /api/health` — database connectivity check.
- `POST /api/auth/sign-up` — creates a seeker or astrologer account.
- `POST /api/auth/sign-in` — signs in a normal account.
- `POST /api/developer/sign-in` — signs in only an approved developer account.
- `GET /api/auth/session` — returns the current cookie session.
- `POST /api/auth/sign-out` — revokes the current session.
- `GET /api/bots` — returns enabled, AI-labelled bots.
- `GET /api/developer/bots` — lists all bots for the developer.
- `PATCH /api/developer/bots/:id` — changes a bot's enabled state.

Passwords are PBKDF2-HMAC-SHA256 hashes. Sessions use random bearer tokens stored only as SHA-256 hashes in Postgres and sent to the browser as HttpOnly, Secure, SameSite=Strict cookies. Developer writes require a verified database role and same-origin requests.

## Existing Vaani database

Neon project: `patient-queen-35360127`  
Database: `vaani`  
Region: `aws-ap-southeast-1`

The project already contains the `app_users`, `app_sessions`, and `ai_bots` tables and the developer/bot seed records.

## Local development

1. Install Node.js 22.12+ and npm.
2. Run `npm install`.
3. Create `.dev.vars` (never commit it) containing:

   ```dotenv
   DATABASE_URL="YOUR_VAANI_NEON_CONNECTION_STRING"
   ```

4. Run `npm run dev`.
5. Open the local Worker URL. Static files and `/api/*` are served from the same origin.

## Cloudflare deployment

1. In the Neon dashboard, select project `vaani-platform`, branch `main`, database `vaani`, and copy its pooled connection string.
2. From the repository root run `npx wrangler secret put DATABASE_URL` and paste the connection string when prompted. Do not add it to `wrangler.toml`, `package.json`, or Git.
3. Run `npm run deploy`.
4. Attach the Vaani site's custom domain to this Worker in Cloudflare. The SPA and API must share the same origin because the frontend calls relative `/api/*` routes and the session cookie is same-site.

## Developer account

The database contains the seeded developer account `developer@vaani.app`. Its password is verified against the PBKDF2 hash stored in `app_users`; no plaintext password is stored in this repository.

## Bot behavior

Five AI accounts are stored in `ai_bots`. Each has a persistent `enabled` flag. Enabling a bot makes it visible through `GET /api/bots`; this backend does not yet schedule or generate feed posts for them. AI identities must remain labelled as AI.
