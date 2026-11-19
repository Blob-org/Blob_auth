import { errors, jwtVerify, SignJWT } from "jose";
import type { Db, User } from "./db";
import { docsRoutes } from "./docs";
import { ALG, type SigningKey } from "./keys";
import type { LogFields, Logger } from "./log";
import {
    generateRecoveryCodes,
    looksLikeRecoveryCode,
    matchTotp,
    newTotpSecret,
    otpauthUrl,
    type SecretBox,
} from "./mfa";
import { createRateLimiter } from "./rateLimit";

export type AuthConfig = {
    db: Db;
    key: SigningKey;
    issuer: string;
    audience: string[];
    corsOrigin: string;
    accessTtlSeconds: number;
    refreshTtlSeconds: number;
    cookieSecure: boolean;
    rateLimit: { limit: number; windowMs: number };
    // Only behind a proxy that sets X-Forwarded-For, such as api_gateway.
    trustProxy: boolean;
    // Called with DELETE and the user's own access token before an account
    // is deleted, so other services erase that user's data (GDPR).
    eraseUrls: string[];
    logger: Logger;
    mfa: {
        box: SecretBox;
        // Shown as the account's name in authenticator apps.
        issuer: string;
        // How long the user has to enter a code after the password step.
        tokenTtlSeconds: number;
        // Wrong codes allowed per password step before starting over.
        maxAttempts: number;
    };
};

// Per-request state: a logger that adds the request id to every line, and the
// user id once the request is authenticated (it goes on the access log line).
export type RequestContext = {
    log: Logger;
    requestId: string;
    userId?: string;
};

type Handler<R extends Request> = (
    request: R,
    server: Bun.Server<unknown>,
    ctx: RequestContext,
) => Response | Promise<Response>;

const REFRESH_COOKIE = "refresh_token";
// Audience of the short-lived token between the password and code steps.
// Only /login/mfa accepts it: authenticate() and the other services check
// for their own audience.
const MFA_AUDIENCE = "mfa";
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const requestIdPattern = /^[A-Za-z0-9._-]{1,128}$/;

// Compared against when the email is unknown, so a failed login takes the same
// time whether or not the account exists.
const dummyHash = await Bun.password.hash("timing-equalizer");

const sha256 = (value: string) =>
    new Bun.CryptoHasher("sha256").update(value).digest("hex");

// "alice@example.com" -> "a***@example.com", so logs can be correlated without
// holding the address.
export function maskEmail(email: string) {
    const at = email.lastIndexOf("@");
    return at > 0 ? `${email[0]}***${email.slice(at)}` : "***";
}

function withFields(log: Logger, base: LogFields): Logger {
    return {
        debug: (message, fields) => log.debug(message, { ...base, ...fields }),
        info: (message, fields) => log.info(message, { ...base, ...fields }),
        warn: (message, fields) => log.warn(message, { ...base, ...fields }),
        error: (message, fields) => log.error(message, { ...base, ...fields }),
    };
}

// Wraps a handler with the request id (taken from the gateway's X-Request-Id
// or generated), echoes it on the response, and writes one access log line.
// `route` is the pattern, never the raw URL, so query strings stay out of logs.
export function instrument<R extends Request>(
    logger: Logger,
    route: string,
    handler: Handler<R>,
) {
    return async (request: R, server: Bun.Server<unknown>) => {
        const start = performance.now();
        const incoming = request.headers.get("x-request-id") ?? "";
        const requestId = requestIdPattern.test(incoming)
            ? incoming
            : crypto.randomUUID();
        const ctx: RequestContext = {
            requestId,
            log: withFields(logger, { requestId }),
        };

        let response: Response;
        try {
            response = await handler(request, server, ctx);
        } catch (err) {
            ctx.log.error("unhandled error", { route, error: String(err) });
            response = Response.json(
                { error: "Internal server error" },
                { status: 500 },
            );
        }
        response.headers.set("X-Request-Id", requestId);
        ctx.log.info("request", {
            method: request.method,
            route,
            status: response.status,
            ms: Math.round(performance.now() - start),
            ...(ctx.userId ? { userId: ctx.userId } : {}),
        });
        return response;
    };
}

type RouteTable = Record<string, Record<string, Handler<Bun.BunRequest>>>;

function instrumentAll<T extends RouteTable>(logger: Logger, table: T) {
    return Object.fromEntries(
        Object.entries(table).map(([route, methods]) => [
            route,
            Object.fromEntries(
                Object.entries(methods).map(([method, handler]) => [
                    method,
                    instrument(logger, route, handler),
                ]),
            ),
        ]),
    ) as {
        [P in keyof T]: {
            [M in keyof T[P]]: (
                request: Bun.BunRequest,
                server: Bun.Server<unknown>,
            ) => Promise<Response>;
        };
    };
}

export function createRoutes(config: AuthConfig) {
    const { db, key } = config;
    const allow = createRateLimiter(config.rateLimit);

    const corsHeaders = {
        "Access-Control-Allow-Origin": config.corsOrigin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
        "Access-Control-Expose-Headers": "X-Request-Id",
        Vary: "Origin",
    };

    const json = (body: unknown, status = 200) =>
        Response.json(body, { status, headers: corsHeaders });

    const preflight = () =>
        new Response(null, { status: 204, headers: corsHeaders });

    async function readBody(request: Request) {
        const body = await request.json().catch(() => null);
        return (body && typeof body === "object" ? body : {}) as Record<
            string,
            unknown
        >;
    }

    const field = (body: Record<string, unknown>, name: string) => {
        const value = body[name];
        return typeof value === "string" ? value : "";
    };

    async function readCredentials(request: Request) {
        const body = await readBody(request);
        return {
            email: field(body, "email").trim().toLowerCase(),
            password: field(body, "password"),
        };
    }

    // `amr` says how the user signed in (RFC 8176), so a service can require
    // a second factor for sensitive actions without asking auth_service.
    function signAccessToken(userId: string, mfa: boolean) {
        return new SignJWT({ amr: mfa ? ["pwd", "otp"] : ["pwd"] })
            .setProtectedHeader({ alg: ALG, kid: key.kid })
            .setSubject(userId)
            .setIssuer(config.issuer)
            .setAudience(config.audience)
            .setIssuedAt()
            .setExpirationTime(`${config.accessTtlSeconds}s`)
            .sign(key.privateKey);
    }

    // The user behind a valid `Authorization: Bearer` access token, if any.
    async function authenticate(request: Request) {
        const header = request.headers.get("authorization") ?? "";
        const token = header.startsWith("Bearer ") ? header.slice(7) : "";
        const payload = await jwtVerify(token, key.publicKey, {
            issuer: config.issuer,
            // Without this, any token signed by this key would pass,
            // including the step-two token issued before the MFA code.
            audience: config.audience,
            algorithms: [ALG],
        })
            .then((result) => result.payload)
            .catch(() => null);
        return payload?.sub ? db.findUserById(payload.sub) : null;
    }

    function issueRefreshToken(
        request: Bun.BunRequest,
        userId: string,
        mfa: boolean,
    ) {
        const token = Buffer.from(
            crypto.getRandomValues(new Uint8Array(32)),
        ).toString("base64url");
        db.insertRefreshToken(
            userId,
            sha256(token),
            Date.now() + config.refreshTtlSeconds * 1000,
            mfa,
        );
        request.cookies.set(REFRESH_COOKIE, token, {
            httpOnly: true,
            secure: config.cookieSecure,
            sameSite: "strict",
            path: "/",
            maxAge: config.refreshTtlSeconds,
        });
    }

    function clearRefreshCookie(request: Bun.BunRequest) {
        request.cookies.delete({ name: REFRESH_COOKIE, path: "/" });
    }

    function signMfaToken(userId: string) {
        return new SignJWT({})
            .setProtectedHeader({ alg: ALG, kid: key.kid })
            .setSubject(userId)
            .setIssuer(config.issuer)
            .setAudience(MFA_AUDIENCE)
            .setJti(crypto.randomUUID())
            .setIssuedAt()
            .setExpirationTime(`${config.mfa.tokenTtlSeconds}s`)
            .sign(key.privateKey);
    }

    async function readMfaToken(
        token: string,
    ): Promise<
        | { userId: string; jti: string; expiresAt: number }
        | { error: "expired_token" | "invalid_token" }
    > {
        try {
            const { payload } = await jwtVerify(token, key.publicKey, {
                issuer: config.issuer,
                audience: MFA_AUDIENCE,
                algorithms: [ALG],
            });
            if (!payload.sub || !payload.jti || !payload.exp) {
                return { error: "invalid_token" };
            }
            return {
                userId: payload.sub,
                jti: payload.jti,
                expiresAt: payload.exp * 1000,
            };
        } catch (error) {
            return {
                error:
                    error instanceof errors.JWTExpired
                        ? "expired_token"
                        : "invalid_token",
            };
        }
    }

    // Wrong codes per step-two token, in memory like the rate limiter. A
    // token that reached the limit, or was already used to sign in, is
    // refused until it expires.
    const mfaAttempts = new Map<string, { count: number; expiresAt: number }>();
    function mfaAttemptsLeft(jti: string) {
        const now = Date.now();
        for (const [id, entry] of mfaAttempts) {
            if (entry.expiresAt <= now) mfaAttempts.delete(id);
        }
        return config.mfa.maxAttempts - (mfaAttempts.get(jti)?.count ?? 0);
    }
    function recordMfaAttempt(jti: string, expiresAt: number, count = 1) {
        const entry = mfaAttempts.get(jti) ?? { count: 0, expiresAt };
        entry.count += count;
        mfaAttempts.set(jti, entry);
    }

    // Accepts a current TOTP code or an unused recovery code, and uses it up
    // so it can't be replayed. Null when it's wrong or already used.
    async function checkSecondFactor(
        user: User,
        code: string,
    ): Promise<"totp" | "recovery" | null> {
        if (!user.totp_secret || !user.totp_enabled_at) return null;
        if (looksLikeRecoveryCode(code)) {
            const hash = await config.mfa.box.hashRecoveryCode(code);
            return db.useRecoveryCode(user.id, hash) ? "recovery" : null;
        }
        const secret = await config.mfa.box.decrypt(user.totp_secret);
        const step = matchTotp(secret, code);
        if (step === null) return null;
        return db.claimTotpStep(user.id, step) ? "totp" : null;
    }

    // Behind the API gateway every request comes from the gateway's address.
    // With trustProxy, the client is the last X-Forwarded-For entry: the one
    // the gateway appended, which a client can't forge.
    function clientIp(request: Request, server: Bun.Server<unknown>) {
        const forwarded = config.trustProxy
            ? request.headers.get("x-forwarded-for")?.split(",").at(-1)?.trim()
            : undefined;
        return forwarded || server.requestIP(request)?.address || "unknown";
    }

    return instrumentAll(config.logger, {
        ...docsRoutes,

        "/register": {
            OPTIONS: preflight,
            POST: async (request, server, { log }) => {
                const ip = clientIp(request, server);
                if (!allow(ip)) {
                    log.warn("register rejected", {
                        reason: "rate_limited",
                        clientIp: ip,
                    });
                    return json({ error: "Too many requests" }, 429);
                }
                const { email, password } = await readCredentials(request);
                const reject = (reason: string) =>
                    log.warn("register rejected", {
                        reason,
                        email: maskEmail(email),
                    });
                if (!emailPattern.test(email) || email.length > 254) {
                    reject("invalid_email");
                    return json({ error: "Invalid email" }, 400);
                }
                if (password.length < 8 || password.length > 256) {
                    reject("invalid_password");
                    return json(
                        { error: "Password must be 8-256 characters" },
                        400,
                    );
                }
                if (db.findUserByEmail(email)) {
                    reject("duplicate");
                    return json({ error: "Email already registered" }, 409);
                }

                const user = db.createUser(
                    email,
                    await Bun.password.hash(password),
                );
                log.info("user registered", { userId: user.id });
                return json({ id: user.id, email: user.email }, 201);
            },
        },

        "/login": {
            OPTIONS: preflight,
            POST: async (request, server, ctx) => {
                const ip = clientIp(request, server);
                if (!allow(ip)) {
                    ctx.log.warn("login rate limited", { clientIp: ip });
                    return json({ error: "Too many requests" }, 429);
                }
                const { email, password } = await readCredentials(request);
                const user = db.findUserByEmail(email);
                const valid = await Bun.password.verify(
                    password,
                    user?.password_hash ?? dummyHash,
                );
                if (!user || !valid) {
                    // The reason is for operators only; the client gets the
                    // same response either way.
                    ctx.log.warn("login failed", {
                        email: maskEmail(email),
                        clientIp: ip,
                        reason: user ? "wrong_password" : "unknown_email",
                    });
                    return json({ error: "Invalid email or password" }, 401);
                }

                ctx.userId = user.id;
                if (user.totp_enabled_at) {
                    // Password is right; no session until the code is too.
                    ctx.log.info("mfa challenge issued", {
                        userId: user.id,
                        clientIp: ip,
                    });
                    return json({
                        mfaRequired: true,
                        mfaToken: await signMfaToken(user.id),
                    });
                }

                issueRefreshToken(request, user.id, false);
                ctx.log.info("login succeeded", {
                    userId: user.id,
                    clientIp: ip,
                });
                return json({
                    accessToken: await signAccessToken(user.id, false),
                });
            },
        },

        "/login/mfa": {
            OPTIONS: preflight,
            POST: async (request, server, ctx) => {
                const ip = clientIp(request, server);
                if (!allow(ip)) {
                    ctx.log.warn("mfa rate limited", { clientIp: ip });
                    return json({ error: "Too many requests" }, 429);
                }
                const body = await readBody(request);
                const restart = (reason: string, userId?: string) => {
                    ctx.log.warn("mfa failed", {
                        reason,
                        clientIp: ip,
                        ...(userId ? { userId } : {}),
                    });
                    return json(
                        {
                            error: "Your sign-in expired. Sign in again.",
                            restart: true,
                        },
                        401,
                    );
                };

                const claims = await readMfaToken(field(body, "mfaToken"));
                if ("error" in claims) return restart(claims.error);
                ctx.userId = claims.userId;
                if (mfaAttemptsLeft(claims.jti) <= 0) {
                    return restart("too_many_attempts", claims.userId);
                }
                const user = db.findUserById(claims.userId);
                if (!user?.totp_enabled_at) {
                    return restart("invalid_token", claims.userId);
                }

                const factor = await checkSecondFactor(
                    user,
                    field(body, "code"),
                );
                if (!factor) {
                    recordMfaAttempt(claims.jti, claims.expiresAt);
                    if (mfaAttemptsLeft(claims.jti) <= 0) {
                        return restart("too_many_attempts", user.id);
                    }
                    ctx.log.warn("mfa failed", {
                        reason: "wrong_code",
                        userId: user.id,
                        clientIp: ip,
                    });
                    return json({ error: "Invalid code" }, 401);
                }
                // One sign-in per step-two token.
                recordMfaAttempt(
                    claims.jti,
                    claims.expiresAt,
                    config.mfa.maxAttempts,
                );
                if (factor === "recovery") {
                    ctx.log.warn("recovery code used", {
                        userId: user.id,
                        remaining: db.countUnusedRecoveryCodes(user.id),
                    });
                }

                issueRefreshToken(request, user.id, true);
                ctx.log.info("login succeeded", {
                    userId: user.id,
                    clientIp: ip,
                    mfa: factor,
                });
                return json({
                    accessToken: await signAccessToken(user.id, true),
                });
            },
        },

        "/mfa/setup": {
            OPTIONS: preflight,
            POST: async (request, _server, ctx) => {
                const user = await authenticate(request);
                if (!user) return json({ error: "Unauthorized" }, 401);
                ctx.userId = user.id;
                if (user.totp_enabled_at) {
                    return json({ error: "MFA is already on" }, 409);
                }
                // Replaces any unfinished setup. MFA stays off until
                // /mfa/enable proves the app has the secret.
                const secret = newTotpSecret();
                db.setTotpSecret(user.id, await config.mfa.box.encrypt(secret));
                ctx.log.info("mfa setup started", { userId: user.id });
                return json({
                    secret,
                    otpauthUrl: otpauthUrl(
                        secret,
                        user.email,
                        config.mfa.issuer,
                    ),
                });
            },
        },

        "/mfa/enable": {
            OPTIONS: preflight,
            POST: async (request, server, ctx) => {
                const ip = clientIp(request, server);
                if (!allow(ip)) {
                    ctx.log.warn("mfa rate limited", { clientIp: ip });
                    return json({ error: "Too many requests" }, 429);
                }
                const user = await authenticate(request);
                if (!user) return json({ error: "Unauthorized" }, 401);
                ctx.userId = user.id;
                if (user.totp_enabled_at) {
                    return json({ error: "MFA is already on" }, 409);
                }
                if (!user.totp_secret) {
                    return json({ error: "Start with /mfa/setup" }, 400);
                }
                const body = await readBody(request);
                const step = matchTotp(
                    await config.mfa.box.decrypt(user.totp_secret),
                    field(body, "code"),
                );
                if (step === null) {
                    ctx.log.warn("mfa failed", {
                        reason: "wrong_code",
                        during: "enable",
                        userId: user.id,
                        clientIp: ip,
                    });
                    return json({ error: "Invalid code" }, 401);
                }

                const recoveryCodes = generateRecoveryCodes();
                db.replaceRecoveryCodes(
                    user.id,
                    await Promise.all(
                        recoveryCodes.map((code) =>
                            config.mfa.box.hashRecoveryCode(code),
                        ),
                    ),
                );
                db.enableTotp(user.id, step);
                ctx.log.info("mfa enabled", { userId: user.id });
                // The only time the plain codes leave the server.
                return json({ recoveryCodes });
            },
        },

        "/mfa/disable": {
            OPTIONS: preflight,
            POST: async (request, server, ctx) => {
                const ip = clientIp(request, server);
                if (!allow(ip)) {
                    ctx.log.warn("mfa rate limited", { clientIp: ip });
                    return json({ error: "Too many requests" }, 429);
                }
                const user = await authenticate(request);
                if (!user) return json({ error: "Unauthorized" }, 401);
                ctx.userId = user.id;
                if (!user.totp_enabled_at) {
                    return json({ error: "MFA is not on" }, 400);
                }
                const body = await readBody(request);
                if (
                    !(await Bun.password.verify(
                        field(body, "password"),
                        user.password_hash,
                    ))
                ) {
                    ctx.log.warn("mfa disable rejected", {
                        reason: "wrong_password",
                        userId: user.id,
                    });
                    return json({ error: "Wrong password" }, 401);
                }
                if (!(await checkSecondFactor(user, field(body, "code")))) {
                    ctx.log.warn("mfa failed", {
                        reason: "wrong_code",
                        during: "disable",
                        userId: user.id,
                        clientIp: ip,
                    });
                    return json({ error: "Invalid code" }, 401);
                }
                db.disableTotp(user.id);
                ctx.log.info("mfa disabled", { userId: user.id });
                return new Response(null, {
                    status: 204,
                    headers: corsHeaders,
                });
            },
        },

        "/refresh": {
            OPTIONS: preflight,
            POST: async (request, _server, ctx) => {
                const token = request.cookies.get(REFRESH_COOKIE);
                const stored = token
                    ? db.findRefreshToken(sha256(token))
                    : null;
                if (!stored) {
                    ctx.log.info("refresh rejected", {
                        reason: token ? "unknown_token" : "no_cookie",
                    });
                    clearRefreshCookie(request);
                    return json({ error: "Not logged in" }, 401);
                }
                if (stored.revoked_at !== null) {
                    // A rotated-out token was used again: it was probably stolen.
                    // Log the user out everywhere.
                    db.revokeAllForUser(stored.user_id);
                    ctx.log.warn("refresh token reuse detected", {
                        userId: stored.user_id,
                    });
                    clearRefreshCookie(request);
                    return json({ error: "Not logged in" }, 401);
                }
                if (stored.expires_at <= Date.now()) {
                    ctx.log.info("refresh rejected", {
                        reason: "expired",
                        userId: stored.user_id,
                    });
                    clearRefreshCookie(request);
                    return json({ error: "Session expired" }, 401);
                }

                // The session keeps the strength it was opened with.
                const mfa = stored.mfa === 1;
                db.revokeRefreshToken(stored.id);
                issueRefreshToken(request, stored.user_id, mfa);
                ctx.userId = stored.user_id;
                ctx.log.debug("token refreshed", { userId: stored.user_id });
                return json({
                    accessToken: await signAccessToken(stored.user_id, mfa),
                });
            },
        },

        "/logout": {
            OPTIONS: preflight,
            POST: (request, _server, ctx) => {
                const token = request.cookies.get(REFRESH_COOKIE);
                const stored = token
                    ? db.findRefreshToken(sha256(token))
                    : null;
                if (stored) db.revokeRefreshToken(stored.id);
                ctx.userId = stored?.user_id;
                ctx.log.info(
                    "logged out",
                    stored ? { userId: stored.user_id } : {},
                );
                clearRefreshCookie(request);
                return new Response(null, {
                    status: 204,
                    headers: corsHeaders,
                });
            },
        },

        "/me": {
            OPTIONS: preflight,
            GET: async (request, _server, ctx) => {
                const user = await authenticate(request);
                if (!user) {
                    return json({ error: "Unauthorized" }, 401);
                }
                ctx.userId = user.id;
                return json({
                    id: user.id,
                    email: user.email,
                    mfaEnabled: user.totp_enabled_at !== null,
                });
            },
            // GDPR right to erasure. The password is asked again so a stolen
            // access token alone can't delete the account.
            DELETE: async (request, server, ctx) => {
                const ip = clientIp(request, server);
                if (!allow(ip)) {
                    ctx.log.warn("account deletion rejected", {
                        reason: "rate_limited",
                        clientIp: ip,
                    });
                    return json({ error: "Too many requests" }, 429);
                }
                const user = await authenticate(request);
                if (!user) {
                    return json({ error: "Unauthorized" }, 401);
                }
                ctx.userId = user.id;
                const body = await readBody(request);
                if (
                    !(await Bun.password.verify(
                        field(body, "password"),
                        user.password_hash,
                    ))
                ) {
                    ctx.log.warn("account deletion rejected", {
                        reason: "wrong_password",
                        userId: user.id,
                    });
                    return json({ error: "Wrong password" }, 401);
                }
                if (
                    user.totp_enabled_at &&
                    !(await checkSecondFactor(user, field(body, "code")))
                ) {
                    ctx.log.warn("account deletion rejected", {
                        reason: "wrong_code",
                        userId: user.id,
                    });
                    return json({ error: "Invalid code" }, 401);
                }

                // Other services erase first. If one fails the account stays,
                // so the user can retry instead of leaving data nobody can
                // reach. Their erasure is idempotent, so retrying is safe.
                for (const url of config.eraseUrls) {
                    const status = await fetch(url, {
                        method: "DELETE",
                        headers: {
                            Authorization:
                                request.headers.get("authorization") ?? "",
                            "X-Request-Id": ctx.requestId,
                        },
                    })
                        .then((response) => response.status)
                        .catch(() => 0);
                    if (status < 200 || status > 299) {
                        ctx.log.error("account deletion failed", {
                            userId: user.id,
                            service: new URL(url).host,
                            status,
                        });
                        return json(
                            { error: "Could not erase your data, try again" },
                            502,
                        );
                    }
                }

                db.deleteUser(user.id);
                clearRefreshCookie(request);
                ctx.log.info("account deleted", { userId: user.id });
                return new Response(null, {
                    status: 204,
                    headers: corsHeaders,
                });
            },
        },

        "/.well-known/jwks.json": {
            GET: () =>
                Response.json(
                    { keys: [key.publicJwk] },
                    { headers: { "Cache-Control": "public, max-age=300" } },
                ),
        },
    });
}
