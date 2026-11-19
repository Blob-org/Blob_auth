# auth_service

Login service for the Blob_storage system. It stores users, issues short-lived JWT access tokens, and publishes its public key so other services (`blob_storage`, `todos_service`) can check tokens themselves without calling this service.

```
Browser ──login/refresh──▶ auth_service ──▶ SQLite (users, refresh tokens)
   │                          │ /.well-known/jwks.json (public key)
   │ Bearer access token      ▼
   ├──────────────▶ blob_storage  ─┐ verify signature locally
   └──────────────▶ todos_service ─┘
```

## Requirements

- Bun v1.3 or newer

## Getting started

```bash
bun install
cp .env.example .env
bun run gen-key >> .env   # adds AUTH_PRIVATE_KEY (keep it secret)
bun run gen-mfa-key >> .env   # adds MFA_ENCRYPTION_KEY (keep it secret too)
bun run dev               # http://localhost:4000
```

For local development over plain http, set `COOKIE_SECURE=false` in `.env`.

### Run with Docker

```bash
cp .env.example .env && bun run gen-key >> .env && bun run gen-mfa-key >> .env   # once
docker compose up -d --build                      # http://localhost:4000
```

`compose.yaml` reads `AUTH_PRIVATE_KEY` and `MFA_ENCRYPTION_KEY` from `.env` and sets the rest itself (`COOKIE_SECURE=false` for local http). The SQLite database lives in the `auth-data` volume, so users survive restarts. `docker compose down -v` deletes it.

The stack also creates the Docker network `blob-storage`. blob_service's `compose.yaml` joins it and fetches the public keys from `http://auth:4000`, so start this stack first.

## Tokens

| Token | Lifetime | Where it lives |
| --- | --- | --- |
| Access token (JWT, EdDSA) | 15 min | In the frontend's memory. Sent as `Authorization: Bearer <token>` to the other services. |
| Refresh token (random, stored hashed) | 14 days, replaced on every refresh | `httpOnly`, `SameSite=Strict` cookie `refresh_token`. |

Access token claims: `sub` (user id), `iss` (`AUTH_ISSUER`), `aud` (`AUTH_AUDIENCE`), `iat`, `exp`, and `amr`: `["pwd"]`, or `["pwd", "otp"]` when the session was opened with a second factor. Refreshing keeps it, so a service can require MFA for a sensitive action by checking `amr` without calling this service.

If a refresh token that has already been replaced is used again, every session of that user is revoked (likely token theft).

## API

Full reference with request/response schemas: **http://localhost:4000/docs** (Swagger UI). The raw spec is `openapi.yaml`, also served at `/openapi.json`.

| Method & path | Body | Response |
| --- | --- | --- |
| `POST /register` | `{ email, password }` (password 8–256 chars) | `201 { id, email }`, `409` if the email exists |
| `POST /login` | `{ email, password }` | `200 { accessToken }` and sets the refresh cookie, `401` on bad credentials. With MFA on: `200 { mfaRequired: true, mfaToken }` and no cookie |
| `POST /login/mfa` | `{ mfaToken, code }` | `200 { accessToken }` and sets the refresh cookie; `401 { error }` for a wrong code (try again) or `401 { error, restart: true }` to start over |
| `POST /mfa/setup` | – (`Authorization: Bearer …`) | `200 { secret, otpauthUrl }`; `409` if MFA is on |
| `POST /mfa/enable` | `{ code }` (Bearer) | `200 { recoveryCodes }` (shown once); `400` without setup, `401` wrong code |
| `POST /mfa/disable` | `{ password, code }` (Bearer) | `204`; `401` wrong password or code |
| `POST /refresh` | – (uses the cookie) | `200 { accessToken }` and a new cookie, `401` otherwise |
| `POST /logout` | – (uses the cookie) | `204`, revokes the refresh token |
| `GET /me` | – (`Authorization: Bearer …`) | `200 { id, email, mfaEnabled }`, `401` otherwise |
| `DELETE /me` | `{ password, code? }` (`Authorization: Bearer …`; `code` required with MFA on) | `204` and the cookie is cleared; `401` for a bad token or wrong password; `502` if another service couldn't erase the user's data (nothing was deleted, retry) |
| `GET /.well-known/jwks.json` | – | `{ keys: [...] }` public keys |

**Deleting an account (GDPR right to erasure).** `DELETE /me` first calls every URL in `ERASE_URLS` (comma-separated, default `http://localhost:3000/files`, compose uses `http://blob:3000/files`) with `DELETE` and the user's own access token, so each service erases that user's data. Only when all of them return 2xx are the user and their sessions deleted. Add todos_service's erase endpoint to the list once it exists.

**Multi-factor authentication (optional per user).** TOTP codes from any authenticator app (SHA-1, 6 digits, 30 s; the previous and next 30 s also pass), with 10 one-time recovery codes as a fallback.

1. `POST /mfa/setup` returns a secret and an `otpauth://` link for a QR code.
2. `POST /mfa/enable` with a code from the app turns MFA on and returns the recovery codes, once.
3. From then on `POST /login` returns an `mfaToken` instead of a session: a 5-minute JWT with audience `mfa`, so neither this service's `/me` nor the other services accept it. `POST /login/mfa` exchanges it plus a code for the session. Each token allows 5 wrong codes and one sign-in.
4. Each TOTP code works once (the last accepted 30 s step is stored), and so does each recovery code.

TOTP secrets are stored encrypted with AES-256-GCM, and recovery codes as HMAC-SHA-256, both with keys derived from `MFA_ENCRYPTION_KEY`. Losing that key locks every MFA user out until an admin resets them. If a user loses their phone and their recovery codes, check it's really them, then run `bun run reset-mfa <email>` (in Docker: `docker compose exec auth bun run reset-mfa <email>`). It turns MFA off and signs them out everywhere.

`/register`, `/login`, `/login/mfa`, `/mfa/enable`, `/mfa/disable` and `DELETE /me` are rate limited to 20 requests per minute per IP. Behind api_gateway every request comes from the gateway's address, so set `TRUST_PROXY=true` there (compose does): the client IP is then the last `X-Forwarded-For` entry, the one the gateway appended. Leave it `false` when clients reach this service directly, or they could pick their own IP with that header. The browser must call the API with `credentials: "include"` so the refresh cookie is sent; CORS allows only `CORS_ORIGIN`.

```bash
curl -X POST localhost:4000/register -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"password123"}'
curl -i -X POST localhost:4000/login -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"password123"}'
```

## Verifying tokens in another service

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";

const jwks = createRemoteJWKSet(new URL("http://localhost:4000/.well-known/jwks.json"));
const { payload } = await jwtVerify(token, jwks, {
    issuer: "http://localhost:4000",
    audience: "blob_storage",
});
// payload.sub is the user id
```

## Project layout

| Path | What it is |
| --- | --- |
| `src/app.ts` | `startServer(options)`: reads config from options or env and starts `Bun.serve()`. |
| `src/routes.ts` | All routes, token signing, cookies, CORS. |
| `src/db.ts` | `bun:sqlite` schema and queries (`users`, `refresh_tokens`, `recovery_codes`), and adding columns to databases created before them. |
| `src/mfa.ts` | TOTP checking, recovery codes, and encryption of TOTP secrets. |
| `src/keys.ts` | Loads the private JWK and derives the public JWK. |
| `openapi.yaml`, `src/docs.ts` | OpenAPI spec and the `/docs` + `/openapi.json` routes. `src/openapi.test.ts` fails if a route is added or removed without updating the spec. |
| `src/log.ts` | JSON line logger (see [Logging](#logging)). |
| `src/rateLimit.ts` | In-memory per-IP rate limiter. |
| `scripts/gen-key.ts` | Prints a new Ed25519 key as an `.env` line. |
| `scripts/gen-mfa-key.ts` | Prints a new `MFA_ENCRYPTION_KEY` line. |
| `scripts/reset-mfa.ts` | Admin: turns MFA off for a locked-out user and signs them out. |
| `scripts/check-issue.ts` | The PR `issue` check (see [PR rules](#pr-rules)). |
| `.github/workflows/` | `ci.yml`, `pr-checks.yml` (labels, issue), `branch-name.yml`, `release.yml`. |
| `Dockerfile`, `compose.yaml` | Container image and the local Docker stack. |

## Logging

Every line on stdout is one JSON object:

```json
{"time":"2026-10-30T12:00:00.000Z","level":"info","service":"auth","message":"request","requestId":"…","method":"POST","route":"/login","status":200,"ms":42,"userId":"…"}
```

Always present: `time` (ISO 8601), `level`, `service` (`"auth"`), `message`. Lines written while handling a request also have `requestId`: the incoming `X-Request-Id` (api_gateway sends one) if it matches `^[A-Za-z0-9._-]{1,128}$`, otherwise a new UUID. Every response, errors and preflights included, carries it back in `X-Request-Id`.

`LOG_LEVEL` (`debug`, `info`, `warn`, `error`; default `info`) drops lines below that level.

| Message | Level | Fields |
| --- | --- | --- |
| `listening` | info | `port` |
| `request` | info | Access log, one per request: `method`, `route` (the route pattern, `unmatched` for 404s), `status`, `ms`, and `userId` when the request was authenticated |
| `user registered` | info | `userId` |
| `register rejected` | warn | `reason` (`invalid_email`, `invalid_password`, `duplicate`, `rate_limited`), `email` (masked) or `clientIp` |
| `login succeeded` | info | `userId`, `clientIp`, and `mfa` (`totp` or `recovery`) after the code step |
| `mfa challenge issued` | info | `userId`, `clientIp`: the password was right and a code is needed |
| `mfa failed` | warn | `reason` (`wrong_code`, `expired_token`, `invalid_token`, `too_many_attempts`), `clientIp`, `userId` when known, `during` (`enable` or `disable`) outside login |
| `mfa rate limited` | warn | `clientIp` |
| `recovery code used` | warn | `userId`, `remaining` |
| `mfa setup started` / `mfa enabled` / `mfa disabled` | info | `userId` |
| `mfa disable rejected` | warn | `reason` (`wrong_password`), `userId` |
| `mfa reset by admin` | warn | `userId` (from `bun run reset-mfa`) |
| `login failed` | warn | `email` (masked), `clientIp`, `reason` (`unknown_email` or `wrong_password`; the client always gets the same 401) |
| `login rate limited` | warn | `clientIp` |
| `token refreshed` | debug | `userId` |
| `refresh token reuse detected` | warn | `userId`; all of that user's sessions were revoked |
| `refresh rejected` | info | `reason` (`no_cookie`, `unknown_token`, `expired`) |
| `logged out` | info | `userId` when the token was known |
| `account deleted` | info | `userId` |
| `account deletion rejected` | warn | `reason` (`wrong_password` or `wrong_code` with `userId`, or `rate_limited` with `clientIp`) |
| `account deletion failed` | error | `userId`, `service` (host of the erase URL), `status` (`0` when unreachable); the account was kept |
| `unhandled error` | error | `route`, `error` |

`clientIp` honours `TRUST_PROXY` the same way the rate limiter does. Emails are masked as `u***@example.com`. Never logged: passwords, access and refresh tokens, the `Authorization` header, cookies, private keys and query strings.

In Docker the `json-file` driver keeps the logs, rotated at 10 MB × 3 files (`compose.yaml`).

## Checks

| Command | What it does |
| --- | --- |
| `bun test` | Runs the tests (in-memory database, generated key). |
| `bun run typecheck` | `tsc --noEmit` |
| `bun run lint` / `lint:fix` | Biome |

Husky runs Biome on commit. On push, it checks the branch name (see below) and runs typecheck and tests. GitHub Actions runs all three on every push to any branch and on every PR.

**Security** (`.github/workflows/security.yml`, on every PR, on push to `main` and weekly):

| Job | What it checks |
| --- | --- |
| `secrets (gitleaks)` | No secrets anywhere in the git history. |
| `dependencies (bun audit)` | No known vulnerabilities of moderate severity or above in the dependencies. One dev-only advisory is ignored, with the reason given in the workflow. |
| `codeql (…)` | Static analysis of the TypeScript and of the workflow files. Findings appear under the repo's **Security → Code scanning**. |
| `image (trivy)` | Builds the Docker image and fails on HIGH or CRITICAL vulnerabilities that have a fix, or on secrets baked into the image. |

Dependabot (`.github/dependabot.yml`) opens weekly update PRs for dependencies, the base image and the GitHub Actions. It skips releases younger than 14 days. Each release gets an SBOM (`sbom.cdx.json`, CycloneDX) listing everything in the image.

## PR rules

`main` is protected: changes reach it only through a pull request, and these four checks must pass (admins included):

| Check | Requires |
| --- | --- |
| **Lint, typecheck, test** | `ci.yml` passes. |
| **branch-name** | The branch is named `<feat\|fix\|docs\|chore>/<issue number>-short-slug`, e.g. `feat/12-refresh-rotation`. This is also checked by the pre-push hook, so a wrongly named branch can't be pushed. Rename with `git branch -m`. |
| **labels** | At least one of `feature`, `enhancement`, `bug`, `documentation`; none of `wontfix`, `invalid`, `duplicate`. |
| **issue** | The PR references an open issue: `Closes #123` in the description, `#123` in the title, or the number in the branch name. The check tries each referenced number and passes on the first open issue. |

With Claude Code, asking to "ship this" or "open a PR" uses the `ship-pr` skill in `.claude/skills/`, which follows these rules.

## Releases

Pushing a version tag re-runs CI on the tagged commit and, if it passes, publishes a GitHub release with notes grouped by PR label (`.github/release.yml`):

```bash
git switch main && git pull
git tag v1.0.0 && git push origin v1.0.0
```

A tag with a suffix such as `v1.1.0-beta.1` becomes a pre-release.

## Known limitations

- The rate limiter and the count of wrong MFA codes per `mfaToken` are in memory: it resets on restart and isn't shared between instances.
- Only one signing key at a time. To rotate, the JWKS would need to serve the old and new public keys for one access-token lifetime.
