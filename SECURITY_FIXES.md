# Security fixes

This document lists the security and design changes applied to this project, and
the items that still need your attention. The app still builds (`npm run build`
passes) and no AI prompt or feature behaviour was changed — only authorization,
secret handling, input validation and build config.

## ⚠️ Do this first — rotate the exposed secrets

A real `.env` was committed to the repository, including the Supabase
**service-role key** (which bypasses Row Level Security) and the publishable
keys. It has been **removed** from the project, but anything committed to git is
considered compromised. Before deploying:

1. In Supabase → Project Settings → API, **roll the service-role key** (and the
   publishable key if you rotate it there).
2. Set the new values as environment variables on your host (Vercel / Cloudflare),
   never in a committed file. Use `.env.example` as the template.
3. If the repo is public, also purge `.env` from git history
   (`git filter-repo` or BFG) — deleting the file does not remove it from past
   commits.

## Fixed

### Critical
- **Hard-coded admin credentials removed.** `src/lib/admin-setup.functions.ts`
  contained a real admin email and password (`onegrasp@2026`) in source, created
  via an unauthenticated server function. It now reads optional
  `ADMIN_SETUP_EMAIL` / `ADMIN_SETUP_PASSWORD` env vars and does nothing if they
  are unset. The login screen no longer pre-fills an admin email.
- **Unauthenticated privilege escalation closed.** `createUser`
  (`src/lib/user.functions.ts`) used the service-role client with no auth check,
  so anyone could create accounts with any role. It now requires an authenticated
  **admin** (`requireAdmin`).
- **Webhook-key IDOR closed.** `generateWebhookKey` / `getWebhookKey` /
  `revokeWebhookKey` (`src/lib/integrations.functions.ts`) accepted a client-
  supplied `userId` and passed it to an anon-callable `SECURITY DEFINER` RPC, so
  anyone could read, regenerate or revoke **any** user's lead-webhook API key.
  They now derive the user from the caller's session token and use the service
  role. A new migration
  (`supabase/migrations/20260620000000_lock_down_webhook_key_rpc.sql`) revokes
  `anon`/`authenticated` execute on `manage_webhook_key`.

### High
- **All AI endpoints now require authentication.** Every function in
  `src/lib/ai.functions.ts` (askAI, summarizeLead, draftWhatsAppMessage,
  draftFollowUpEmail, parseLeadsFromText, getDashboardRecommendations,
  suggestNextAction) was an open proxy to a paid LLM. Each now calls
  `requireUser` with the caller's token. All call sites were updated to pass
  `session.access_token`.
- **`xlsx` 0.18.5 → SheetJS 0.20.3.** The old package has an unfixed prototype-
  pollution and ReDoS advisory; replaced with the maintained SheetJS build.
- **Meta lead webhook now verifies `X-Hub-Signature-256`** against
  `META_APP_SECRET` (`api/webhook-meta.ts`). When the secret is set the signature
  is required; set it in production to stop forged lead events.
- **Google lead webhook fails closed.** `api/webhook-google.ts` previously
  accepted leads when `GOOGLE_ADS_WEBHOOK_KEY` was unset; it now rejects all
  requests until the key is configured.

### Build / correctness
- **Build was broken** — `@/…` path aliases failed to resolve (tsconfig has no
  `baseUrl`). Added an explicit `resolve.alias` in `vite.config.ts`; `npm run
  build` now succeeds.
- Shared server-side auth guard added at `src/lib/auth-guard.ts`.
- `.gitignore` tightened so real env files can't be committed again.

## Still recommended (not applied here)

- **Dependency upgrades need a major-version bump + runtime testing.** `npm audit`
  still reports advisories, most in build-time tooling (vite, esbuild, postcss,
  wrangler, miniflare, sharp, @babel) that don't ship to production. Two are worth
  prioritising and should be done with the app running so you can verify nothing
  breaks:
  - **TanStack Start / Router** — there is a *reflected-XSS in server-function
    responses* advisory. Upgrade `@tanstack/react-start`, `@tanstack/react-router`
    and `@tanstack/router-plugin` to the latest patched releases together, then
    smoke-test routing, SSR and all server functions.
  - **zod** — memory-exhaustion advisory; bump once the TanStack packages allow it.
  Run `npm audit` to see the current list; avoid `npm audit fix --force` without
  testing, as it bumps majors.
- **Row Level Security is broad.** Core tables (`leads`, `activities`, …) use
  `FOR ALL TO authenticated USING (true)`, so every signed-in user can read and
  write all rows. Fine for a single-team tool; scope by owner/role if you need
  tenant isolation.
- **Two parallel lead-webhook implementations exist** (`src/lib/webhook-leads.ts`
  via the Cloudflare server entry, and `api/webhook-*.ts` for Vercel). Keep only
  the one matching your deploy target to avoid drift.
