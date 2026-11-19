import { Database } from "bun:sqlite";
import { afterEach, expect, setSystemTime, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import { generatePrivateJwk } from "../scripts/gen-key";
import { resetMfa } from "../scripts/reset-mfa";
import { startServer } from "./app";
import { openDb } from "./db";
import { createLogger } from "./log";
import { currentTotpCode, generateMfaKey } from "./mfa";

const servers: { stop: (force?: boolean) => unknown }[] = [];

afterEach(() => {
    for (const server of servers.splice(0)) server.stop(true);
});

type LogLine = Record<string, unknown>;

async function setup(options: Parameters<typeof startServer>[0] = {}) {
    const lines: LogLine[] = [];
    const raw: string[] = [];
    const server = await startServer({
        logger: createLogger({
            service: "auth",
            level: "debug",
            write: (line) => {
                raw.push(line);
                lines.push(JSON.parse(line));
            },
        }),
        port: 0,
        dbPath: ":memory:",
        privateJwk: await generatePrivateJwk(),
        mfaKey: generateMfaKey(),
        issuer: "http://auth.test",
        audience: ["blob_storage"],
        corsOrigin: "http://app.test",
        cookieSecure: false,
        eraseUrls: [],
        ...options,
    });
    servers.push(server);
    const base = `http://127.0.0.1:${server.port}`;

    const post = (path: string, body?: unknown, cookie?: string) =>
        fetch(base + path, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...(cookie ? { Cookie: cookie } : {}),
            },
            body: body === undefined ? undefined : JSON.stringify(body),
        });

    const find = (message: string) =>
        lines.filter((line) => line.message === message);

    return { base, post, lines, raw, find };
}

// "refresh_token=abc; Path=/; HttpOnly" -> "refresh_token=abc"
const cookieFrom = (response: Response) =>
    (response.headers.get("set-cookie") ?? "").split(";")[0] ?? "";

const credentials = { email: "User@Example.com", password: "correct horse" };

test("register, login, /me, and the token verifies against the JWKS", async () => {
    const { base, post } = await setup();

    const registered = await post("/register", credentials);
    expect(registered.status).toBe(201);
    const user = await registered.json();
    expect(user.email).toBe("user@example.com");

    expect((await post("/register", credentials)).status).toBe(409);

    const login = await post("/login", credentials);
    expect(login.status).toBe(200);
    const setCookie = login.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Strict");
    const { accessToken } = await login.json();

    const jwks = await (await fetch(`${base}/.well-known/jwks.json`)).json();
    expect(jwks.keys[0].d).toBeUndefined();
    const { payload } = await jwtVerify(accessToken, createLocalJWKSet(jwks), {
        issuer: "http://auth.test",
        audience: "blob_storage",
    });
    expect(payload.sub).toBe(user.id);

    const me = await fetch(`${base}/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(await me.json()).toEqual({
        id: user.id,
        email: "user@example.com",
        mfaEnabled: false,
    });
    expect((await fetch(`${base}/me`)).status).toBe(401);
});

test("rejects bad input and wrong passwords", async () => {
    const { post } = await setup();

    expect(
        (await post("/register", { email: "nope", password: "12345678" }))
            .status,
    ).toBe(400);
    expect(
        (await post("/register", { email: "a@b.co", password: "short" }))
            .status,
    ).toBe(400);
    expect((await post("/register", undefined)).status).toBe(400);

    await post("/register", credentials);
    expect(
        (await post("/login", { ...credentials, password: "wrong pass" }))
            .status,
    ).toBe(401);
    expect(
        (await post("/login", { email: "x@y.zz", password: "whatever1" }))
            .status,
    ).toBe(401);
});

test("refresh rotates the token; reusing an old one logs the user out everywhere", async () => {
    const { post } = await setup();
    await post("/register", credentials);
    const first = cookieFrom(await post("/login", credentials));

    const refreshed = await post("/refresh", undefined, first);
    expect(refreshed.status).toBe(200);
    expect((await refreshed.json()).accessToken).toBeString();
    const second = cookieFrom(refreshed);
    expect(second).not.toBe(first);

    // Replaying the rotated-out token revokes every session, including `second`.
    expect((await post("/refresh", undefined, first)).status).toBe(401);
    expect((await post("/refresh", undefined, second)).status).toBe(401);
});

test("logout revokes the refresh token", async () => {
    const { post } = await setup();
    await post("/register", credentials);
    const cookie = cookieFrom(await post("/login", credentials));

    expect((await post("/logout", undefined, cookie)).status).toBe(204);
    expect((await post("/refresh", undefined, cookie)).status).toBe(401);
    expect((await post("/refresh")).status).toBe(401);
});

test("expired refresh tokens are rejected", async () => {
    const { post } = await setup({ refreshTtlSeconds: -1 });
    await post("/register", credentials);
    const cookie = cookieFrom(await post("/login", credentials));
    expect((await post("/refresh", undefined, cookie)).status).toBe(401);
});

test("CORS preflight allows only the configured origin with credentials", async () => {
    const { base } = await setup();
    const response = await fetch(`${base}/login`, { method: "OPTIONS" });
    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe(
        "http://app.test",
    );
    expect(response.headers.get("access-control-allow-credentials")).toBe(
        "true",
    );
});

test("rate limits login attempts per IP", async () => {
    const { post } = await setup({ rateLimit: { limit: 2, windowMs: 60_000 } });
    expect((await post("/login", credentials)).status).toBe(401);
    expect((await post("/login", credentials)).status).toBe(401);
    expect((await post("/login", credentials)).status).toBe(429);
});

test("with trustProxy, rate limits by the address the proxy appended", async () => {
    const { base } = await setup({
        rateLimit: { limit: 1, windowMs: 60_000 },
        trustProxy: true,
    });
    const login = (forwardedFor: string) =>
        fetch(`${base}/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Forwarded-For": forwardedFor,
            },
            body: JSON.stringify(credentials),
        });

    expect((await login("10.0.0.1")).status).toBe(401);
    expect((await login("10.0.0.2")).status).toBe(401);
    // A client-supplied first entry doesn't give a fresh budget.
    expect((await login("1.2.3.4, 10.0.0.1")).status).toBe(429);
});

test("without trustProxy, X-Forwarded-For is ignored", async () => {
    const { base } = await setup({ rateLimit: { limit: 1, windowMs: 60_000 } });
    const login = (forwardedFor: string) =>
        fetch(`${base}/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Forwarded-For": forwardedFor,
            },
            body: JSON.stringify(credentials),
        });

    expect((await login("10.0.0.1")).status).toBe(401);
    expect((await login("10.0.0.2")).status).toBe(429);
});

test("logs startup and an access line per request with the route pattern", async () => {
    const { base, post, find } = await setup();
    expect(find("listening")[0]).toMatchObject({
        level: "info",
        service: "auth",
        port: expect.any(Number),
    });

    await post("/register", credentials);
    const { accessToken } = await (await post("/login", credentials)).json();
    const me = await fetch(`${base}/me?secret=abc`, {
        headers: { Authorization: `Bearer ${accessToken}` },
    });
    const { id } = await me.json();
    await fetch(`${base}/nope?x=1`);

    const access = find("request");
    expect(access.map((line) => line.route)).toEqual([
        "/register",
        "/login",
        "/me",
        "unmatched",
    ]);
    const meLine = access[2];
    expect(meLine).toMatchObject({
        level: "info",
        method: "GET",
        route: "/me",
        status: 200,
        userId: id,
        requestId: me.headers.get("x-request-id"),
    });
    expect(Number.isInteger(meLine?.ms)).toBe(true);
    expect(new Date(String(meLine?.time)).toISOString()).toBe(
        String(meLine?.time),
    );
    expect(access[3]).toMatchObject({ status: 404 });
    expect(access[3]?.userId).toBeUndefined();
});

test("echoes a valid X-Request-Id and replaces a missing or invalid one", async () => {
    const { base, lines } = await setup();
    const jwks = `${base}/.well-known/jwks.json`;

    const echoed = await fetch(jwks, {
        headers: { "X-Request-Id": "gw-1.a_b" },
    });
    expect(echoed.headers.get("x-request-id")).toBe("gw-1.a_b");

    const generated = await fetch(jwks);
    const invalid = await fetch(jwks, {
        headers: { "X-Request-Id": "bad id\\n{}" },
    });
    const tooLong = await fetch(jwks, {
        headers: { "X-Request-Id": "a".repeat(129) },
    });
    const uuid = /^[0-9a-f-]{36}$/;
    for (const response of [generated, invalid, tooLong]) {
        expect(response.headers.get("x-request-id")).toMatch(uuid);
    }

    // Errors and preflights carry it too.
    const notFound = await fetch(`${base}/nope`, {
        headers: { "X-Request-Id": "r404" },
    });
    expect(notFound.headers.get("x-request-id")).toBe("r404");
    const options = await fetch(`${base}/login`, {
        method: "OPTIONS",
        headers: { "X-Request-Id": "r-opt" },
    });
    expect(options.status).toBe(204);
    expect(options.headers.get("x-request-id")).toBe("r-opt");

    const ids = lines
        .filter((line) => line.message === "request")
        .map((line) => line.requestId);
    expect(ids).toEqual([
        "gw-1.a_b",
        generated.headers.get("x-request-id"),
        invalid.headers.get("x-request-id"),
        tooLong.headers.get("x-request-id"),
        "r404",
        "r-opt",
    ]);
});

test("logs register and login audit events with masked emails", async () => {
    const { post, find } = await setup();

    const user = await (await post("/register", credentials)).json();
    await post("/register", credentials);
    await post("/register", { email: "nope", password: "12345678" });
    await post("/login", { ...credentials, password: "wrong pass" });
    await post("/login", { email: "x@y.zz", password: "whatever1" });
    await post("/login", credentials);

    expect(find("user registered")).toEqual([
        expect.objectContaining({ level: "info", userId: user.id }),
    ]);
    expect(find("register rejected")).toEqual([
        expect.objectContaining({
            level: "warn",
            reason: "duplicate",
            email: "u***@example.com",
        }),
        expect.objectContaining({ reason: "invalid_email", email: "***" }),
    ]);
    expect(find("login failed")).toEqual([
        expect.objectContaining({
            level: "warn",
            reason: "wrong_password",
            email: "u***@example.com",
            clientIp: expect.any(String),
        }),
        expect.objectContaining({
            reason: "unknown_email",
            email: "x***@y.zz",
        }),
    ]);
    expect(find("login succeeded")).toEqual([
        expect.objectContaining({
            level: "info",
            userId: user.id,
            clientIp: expect.any(String),
        }),
    ]);
    // Every audit line belongs to its request.
    for (const line of find("login failed")) {
        expect(line.requestId).toBeString();
    }
});

test("logs rate limiting with the proxy-aware client IP", async () => {
    const { base, find } = await setup({
        rateLimit: { limit: 1, windowMs: 60_000 },
        trustProxy: true,
    });
    const login = () =>
        fetch(`${base}/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Forwarded-For": "1.2.3.4, 10.0.0.7",
            },
            body: JSON.stringify(credentials),
        });
    await login();
    expect((await login()).status).toBe(429);
    expect(find("login rate limited")).toEqual([
        expect.objectContaining({ level: "warn", clientIp: "10.0.0.7" }),
    ]);
});

test("logs refresh, reuse detection, rejections and logout", async () => {
    const { post, find } = await setup();
    const { id } = await (await post("/register", credentials)).json();
    const first = cookieFrom(await post("/login", credentials));
    const second = cookieFrom(await post("/refresh", undefined, first));
    await post("/refresh", undefined, first);
    await post("/refresh");

    expect(find("token refreshed")).toEqual([
        expect.objectContaining({ level: "debug", userId: id }),
    ]);
    expect(find("refresh token reuse detected")).toEqual([
        expect.objectContaining({ level: "warn", userId: id }),
    ]);
    expect(find("refresh rejected")).toEqual([
        expect.objectContaining({ level: "info", reason: "no_cookie" }),
    ]);

    const third = cookieFrom(await post("/login", credentials));
    await post("/logout", undefined, third);
    await post("/logout", undefined, second);
    expect(find("logged out")).toEqual([
        expect.objectContaining({ level: "info", userId: id }),
        expect.objectContaining({ level: "info", userId: id }),
    ]);
    await post("/logout");
    expect(find("logged out")[2]?.userId).toBeUndefined();
});

test("logs expired refresh tokens", async () => {
    const { post, find } = await setup({ refreshTtlSeconds: -1 });
    await post("/register", credentials);
    await post(
        "/refresh",
        undefined,
        cookieFrom(await post("/login", credentials)),
    );
    expect(find("refresh rejected")).toEqual([
        expect.objectContaining({ reason: "expired" }),
    ]);
});

test("never logs passwords, tokens, cookies or the plain email", async () => {
    const { base, post, raw } = await setup();
    await post("/register", credentials);
    await post("/login", { ...credentials, password: "wrong pass" });
    const login = await post("/login", credentials);
    const cookie = cookieFrom(login);
    const { accessToken } = await login.json();
    await fetch(`${base}/me`, {
        headers: { Authorization: `Bearer ${accessToken}`, Cookie: cookie },
    });
    const refreshed = await post("/refresh", undefined, cookie);
    const { accessToken: secondToken } = await refreshed.json();
    await post("/logout", undefined, cookieFrom(refreshed));

    const output = raw.join("\n").toLowerCase();
    const secrets = [
        credentials.password,
        "wrong pass",
        credentials.email,
        accessToken,
        secondToken,
        cookie.split("=")[1],
        cookieFrom(refreshed).split("=")[1],
    ];
    for (const secret of secrets) {
        expect(secret).toBeTruthy();
        expect(output).not.toContain(String(secret).toLowerCase());
    }
    expect(output).not.toContain("authorization");
    expect(output).not.toContain("cookie");
});

test("LOG_LEVEL drops lines below the configured level", () => {
    const write = (into: string[]) => (line: string) => into.push(line);
    const levels = (level: string | undefined) => {
        const out: string[] = [];
        const log = createLogger({ service: "auth", level, write: write(out) });
        log.debug("d");
        log.info("i");
        log.warn("w");
        log.error("e", { error: String(new Error("boom")) });
        return out.map((line) => JSON.parse(line).level);
    };
    expect(levels("debug")).toEqual(["debug", "info", "warn", "error"]);
    expect(levels("warn")).toEqual(["warn", "error"]);
    expect(levels("error")).toEqual(["error"]);
    expect(levels("")).toEqual(["info", "warn", "error"]);
    expect(levels("loud")).toEqual(["info", "warn", "error"]);
});

// Stands in for Blob_storage's DELETE /files and records what it received.
function fakeBlob(status = 200) {
    const calls: { method: string; authorization: string | null }[] = [];
    const server = Bun.serve({
        port: 0,
        fetch(request) {
            calls.push({
                method: request.method,
                authorization: request.headers.get("authorization"),
            });
            return Response.json({ deleted: 0 }, { status });
        },
    });
    servers.push(server);
    return { url: `http://127.0.0.1:${server.port}/files`, calls };
}

async function signedIn(
    post: (path: string, body?: unknown) => Promise<Response>,
) {
    await post("/register", credentials);
    const login = await post("/login", credentials);
    const { accessToken } = await login.json();
    return { accessToken, cookie: cookieFrom(login) };
}

function deleteAccount(base: string, accessToken: string, password: string) {
    return fetch(`${base}/me`, {
        method: "DELETE",
        headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ password }),
    });
}

test("DELETE /me erases the user's files, then the account and sessions", async () => {
    const blob = fakeBlob();
    const { base, post, find } = await setup({ eraseUrls: [blob.url] });
    const { accessToken, cookie } = await signedIn(post);

    const response = await deleteAccount(
        base,
        accessToken,
        credentials.password,
    );

    expect(response.status).toBe(204);
    expect(blob.calls).toEqual([
        { method: "DELETE", authorization: `Bearer ${accessToken}` },
    ]);
    expect(
        (
            await fetch(`${base}/me`, {
                headers: { Authorization: `Bearer ${accessToken}` },
            })
        ).status,
    ).toBe(401);
    expect((await post("/refresh", undefined, cookie)).status).toBe(401);
    expect((await post("/login", credentials)).status).toBe(401);
    expect(find("account deleted")).toHaveLength(1);
});

test("DELETE /me needs the right password and a valid token", async () => {
    const blob = fakeBlob();
    const { base, post, find } = await setup({ eraseUrls: [blob.url] });
    const { accessToken } = await signedIn(post);

    expect(
        (await deleteAccount(base, accessToken, "wrong password")).status,
    ).toBe(401);
    expect(
        (await deleteAccount(base, "not-a-jwt", credentials.password)).status,
    ).toBe(401);

    expect(blob.calls).toEqual([]);
    expect((await post("/login", credentials)).status).toBe(200);
    expect(find("account deletion rejected")).toMatchObject([
        { reason: "wrong_password" },
    ]);
});

test("DELETE /me keeps the account when erasure fails", async () => {
    const failing = fakeBlob(502);
    const { base, post, find } = await setup({
        // The second URL is never reached: the first failure stops it.
        eraseUrls: [failing.url, "http://127.0.0.1:1/files"],
    });
    const { accessToken } = await signedIn(post);

    const response = await deleteAccount(
        base,
        accessToken,
        credentials.password,
    );

    expect(response.status).toBe(502);
    expect((await post("/login", credentials)).status).toBe(200);
    expect(find("account deletion failed")).toMatchObject([{ status: 502 }]);
});

test("DELETE /me keeps the account when a service is unreachable", async () => {
    const { base, post, find } = await setup({
        eraseUrls: ["http://127.0.0.1:1/files"],
    });
    const { accessToken } = await signedIn(post);

    expect(
        (await deleteAccount(base, accessToken, credentials.password)).status,
    ).toBe(502);
    expect((await post("/login", credentials)).status).toBe(200);
    expect(find("account deletion failed")).toMatchObject([{ status: 0 }]);
});

test("account deletion logs no email, password or token", async () => {
    const blob = fakeBlob();
    const { base, post, raw } = await setup({ eraseUrls: [blob.url] });
    const { accessToken } = await signedIn(post);
    await deleteAccount(base, accessToken, credentials.password);

    const all = raw.join("\n");
    expect(all).not.toContain(accessToken);
    expect(all).not.toContain(credentials.password);
    expect(all.toLowerCase()).not.toContain(credentials.email.toLowerCase());
});

// --- multi-factor authentication ---

// TOTP codes depend on the clock, and each 30-second step can be used once,
// so these tests move time forward explicitly.
let clock = 0;
function startClock() {
    clock = Date.UTC(2026, 10, 17, 12, 0, 5);
    setSystemTime(new Date(clock));
}
function advance(seconds: number) {
    clock += seconds * 1000;
    setSystemTime(new Date(clock));
}
afterEach(() => {
    setSystemTime();
});

// A 6-digit code that is valid in none of the accepted windows.
function wrongCode(secret: string) {
    const valid = new Set(
        [-30_000, 0, 30_000].map((d) => currentTotpCode(secret, clock + d)),
    );
    for (let n = 0; ; n++) {
        const code = String(n).padStart(6, "0");
        if (!valid.has(code)) return code;
    }
}

async function setupWithMfa(options: Parameters<typeof setup>[0] = {}) {
    startClock();
    const ctx = await setup(options);
    const { accessToken, cookie } = await signedIn(ctx.post);
    const call = (path: string, body?: unknown, token = accessToken) =>
        fetch(ctx.base + path, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
    const setupResponse = await call("/mfa/setup");
    const { secret, otpauthUrl } = await setupResponse.json();
    const enabled = await call("/mfa/enable", {
        code: currentTotpCode(secret),
    });
    const { recoveryCodes } = await enabled.json();
    // The code used to enable is spent; later steps need a new window.
    advance(30);

    // Password step, then the code step.
    const passwordStep = async () =>
        (await (await ctx.post("/login", credentials)).json()) as {
            mfaRequired?: boolean;
            mfaToken: string;
            accessToken?: string;
        };
    const codeStep = (mfaToken: string, code: string) =>
        ctx.post("/login/mfa", { mfaToken, code });

    return {
        ...ctx,
        call,
        accessToken,
        cookie,
        secret: secret as string,
        otpauthUrl: otpauthUrl as string,
        recoveryCodes: recoveryCodes as string[],
        setupStatus: setupResponse.status,
        enableStatus: enabled.status,
        passwordStep,
        codeStep,
    };
}

test("MFA setup returns a secret and link; enabling needs a valid code", async () => {
    startClock();
    const db = openDb(":memory:");
    const { base, post } = await setup({ db });
    const { accessToken } = await signedIn(post);
    const call = (path: string, body?: unknown) =>
        fetch(base + path, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${accessToken}`,
                "Content-Type": "application/json",
            },
            body: body === undefined ? undefined : JSON.stringify(body),
        });

    expect((await call("/mfa/enable", { code: "123456" })).status).toBe(400);

    const setupResponse = await call("/mfa/setup");
    expect(setupResponse.status).toBe(200);
    const { secret, otpauthUrl } = await setupResponse.json();
    expect(otpauthUrl).toStartWith("otpauth://totp/");
    expect(otpauthUrl).toContain(`secret=${secret}`);

    // Stored encrypted, and not yet enabled.
    const stored = db.findUserByEmail("user@example.com");
    expect(stored?.totp_secret).not.toContain(secret);
    expect(stored?.totp_enabled_at).toBeNull();

    expect(
        (await call("/mfa/enable", { code: wrongCode(secret) })).status,
    ).toBe(401);
    const enabled = await call("/mfa/enable", {
        code: currentTotpCode(secret),
    });
    expect(enabled.status).toBe(200);
    const { recoveryCodes } = await enabled.json();
    expect(recoveryCodes).toHaveLength(10);

    const me = await fetch(`${base}/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect((await me.json()).mfaEnabled).toBe(true);
    expect((await call("/mfa/setup")).status).toBe(409);
    expect((await call("/mfa/enable", { code: "123456" })).status).toBe(409);
});

test("login with MFA takes a code; the session carries amr and refresh keeps it", async () => {
    const { base, post, passwordStep, codeStep, secret, find } =
        await setupWithMfa();

    const login = await post("/login", credentials);
    expect(login.headers.get("set-cookie")).toBeNull();
    const { mfaRequired, mfaToken, accessToken } = await login.json();
    expect(mfaRequired).toBe(true);
    expect(accessToken).toBeUndefined();

    // The step-two token is not an access token.
    const asBearer = { Authorization: `Bearer ${mfaToken}` };
    expect((await fetch(`${base}/me`, { headers: asBearer })).status).toBe(401);
    expect(
        (
            await fetch(`${base}/mfa/setup`, {
                method: "POST",
                headers: asBearer,
            })
        ).status,
    ).toBe(401);

    const done = await codeStep(mfaToken, currentTotpCode(secret));
    expect(done.status).toBe(200);
    const session = await done.json();
    expect(decodeJwt(session.accessToken).amr).toEqual(["pwd", "otp"]);

    const refreshed = await post("/refresh", undefined, cookieFrom(done));
    expect(refreshed.status).toBe(200);
    expect(decodeJwt((await refreshed.json()).accessToken).amr).toEqual([
        "pwd",
        "otp",
    ]);

    expect(find("login succeeded").at(-1)).toMatchObject({ mfa: "totp" });
    expect((await passwordStep()).mfaRequired).toBe(true);
    expect(find("mfa challenge issued")).toHaveLength(2);
});

test("users without MFA still log in in one step, with amr pwd", async () => {
    const { post } = await setup();
    await post("/register", credentials);
    const login = await post("/login", credentials);
    const { accessToken, mfaRequired } = await login.json();
    expect(mfaRequired).toBeUndefined();
    expect(decodeJwt(accessToken).amr).toEqual(["pwd"]);
});

test("a TOTP code works once; the previous window still passes", async () => {
    const { passwordStep, codeStep, secret } = await setupWithMfa();
    advance(30);
    // The previous window's code, which hasn't been used yet.
    const previous = currentTotpCode(secret, clock - 30_000);

    const first = await passwordStep();
    expect((await codeStep(first.mfaToken, previous)).status).toBe(200);

    const second = await passwordStep();
    const replay = await codeStep(second.mfaToken, previous);
    expect(replay.status).toBe(401);
    expect(await replay.json()).toEqual({ error: "Invalid code" });

    expect(
        (await codeStep(second.mfaToken, currentTotpCode(secret))).status,
    ).toBe(200);
});

test("wrong codes use up the step-two token", async () => {
    const { passwordStep, codeStep, secret, find } = await setupWithMfa();
    const { mfaToken } = await passwordStep();

    for (let i = 0; i < 4; i++) {
        const response = await codeStep(mfaToken, wrongCode(secret));
        expect(response.status).toBe(401);
        expect((await response.json()).restart).toBeUndefined();
    }
    const fifth = await codeStep(mfaToken, wrongCode(secret));
    expect((await fifth.json()).restart).toBe(true);

    // Even the right code is refused now; the user starts over.
    const late = await codeStep(mfaToken, currentTotpCode(secret));
    expect(late.status).toBe(401);
    expect((await late.json()).restart).toBe(true);
    expect(
        find("mfa failed").filter((l) => l.reason === "too_many_attempts"),
    ).toHaveLength(2);

    const fresh = await passwordStep();
    expect(
        (await codeStep(fresh.mfaToken, currentTotpCode(secret))).status,
    ).toBe(200);
});

test("a step-two token expires and can't be used twice", async () => {
    const { passwordStep, codeStep, secret, find } = await setupWithMfa();

    const { mfaToken } = await passwordStep();
    advance(5 * 60 + 1);
    const expired = await codeStep(mfaToken, currentTotpCode(secret));
    expect(expired.status).toBe(401);
    expect((await expired.json()).restart).toBe(true);
    expect(find("mfa failed").at(-1)).toMatchObject({
        reason: "expired_token",
    });

    const again = await passwordStep();
    expect(
        (await codeStep(again.mfaToken, currentTotpCode(secret))).status,
    ).toBe(200);
    advance(30);
    const reused = await codeStep(again.mfaToken, currentTotpCode(secret));
    expect((await reused.json()).restart).toBe(true);

    expect((await codeStep("not-a-jwt", currentTotpCode(secret))).status).toBe(
        401,
    );
});

test("a recovery code works once, in any case or spacing", async () => {
    const { passwordStep, codeStep, recoveryCodes, find } =
        await setupWithMfa();
    const [code = ""] = recoveryCodes;

    const first = await passwordStep();
    const typed = code.toUpperCase().replace("-", " ");
    expect((await codeStep(first.mfaToken, typed)).status).toBe(200);
    expect(find("recovery code used")).toMatchObject([{ remaining: 9 }]);
    expect(find("login succeeded").at(-1)).toMatchObject({ mfa: "recovery" });

    const second = await passwordStep();
    expect((await codeStep(second.mfaToken, code)).status).toBe(401);
});

test("turning MFA off needs the password and a code", async () => {
    const { call, post, secret, recoveryCodes, base, accessToken } =
        await setupWithMfa();

    const wrongPassword = await call("/mfa/disable", {
        password: "wrong password",
        code: currentTotpCode(secret),
    });
    expect(wrongPassword.status).toBe(401);
    const wrong = await call("/mfa/disable", {
        password: credentials.password,
        code: wrongCode(secret),
    });
    expect(wrong.status).toBe(401);

    const off = await call("/mfa/disable", {
        password: credentials.password,
        code: recoveryCodes[1],
    });
    expect(off.status).toBe(204);

    const me = await fetch(`${base}/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect((await me.json()).mfaEnabled).toBe(false);
    const login = await (await post("/login", credentials)).json();
    expect(typeof login.accessToken).toBe("string");
    expect(
        (
            await call("/mfa/disable", {
                password: credentials.password,
                code: "123456",
            })
        ).status,
    ).toBe(400);
});

test("deleting an account with MFA on needs a code too", async () => {
    const blob = fakeBlob();
    const { base, accessToken, secret, post } = await setupWithMfa({
        eraseUrls: [blob.url],
    });
    const remove = (code?: string) =>
        fetch(`${base}/me`, {
            method: "DELETE",
            headers: {
                Authorization: `Bearer ${accessToken}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ password: credentials.password, code }),
        });

    expect((await remove()).status).toBe(401);
    expect((await remove(wrongCode(secret))).status).toBe(401);
    expect(blob.calls).toEqual([]);

    expect((await remove(currentTotpCode(secret))).status).toBe(204);
    expect(blob.calls).toHaveLength(1);
    expect((await post("/login", credentials)).status).toBe(401);
});

test("MFA logs carry no secrets, codes or tokens", async () => {
    const { raw, passwordStep, codeStep, secret, recoveryCodes } =
        await setupWithMfa();
    const { mfaToken } = await passwordStep();
    const code = currentTotpCode(secret);
    await codeStep(mfaToken, code);
    await codeStep(mfaToken, recoveryCodes[0] ?? "");

    const all = raw.join("\n");
    expect(all).not.toContain(secret);
    expect(all).not.toContain(mfaToken);
    expect(all).not.toContain(`"${code}"`);
    for (const recovery of recoveryCodes) expect(all).not.toContain(recovery);
    expect(all.toLowerCase()).not.toContain(credentials.email.toLowerCase());
});

test("reset-mfa turns MFA off and signs the user out everywhere", async () => {
    const dbPath = join(mkdtempSync(join(tmpdir(), "auth-")), "auth.sqlite");
    const { post, cookie, passwordStep } = await setupWithMfa({ dbPath });
    expect((await passwordStep()).mfaRequired).toBe(true);

    expect(resetMfa(dbPath, "USER@example.com ")).toBeString();
    expect(resetMfa(dbPath, "nobody@example.com")).toBeNull();

    expect((await post("/refresh", undefined, cookie)).status).toBe(401);
    const login = await (await post("/login", credentials)).json();
    expect(typeof login.accessToken).toBe("string");
});

test("opening an older database adds the MFA columns", () => {
    const dbPath = join(mkdtempSync(join(tmpdir(), "auth-")), "old.sqlite");
    const old = new Database(dbPath);
    old.run(`CREATE TABLE users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )`);
    old.run(`CREATE TABLE refresh_tokens (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER
    )`);
    old.run(
        "INSERT INTO users VALUES ('u1', 'old@example.com', 'hash', 1), ('u2', 'x@example.com', 'hash', 1)",
    );
    old.run(
        "INSERT INTO refresh_tokens VALUES ('t1', 'u1', 'th', 9999999999999, NULL)",
    );
    old.close();

    const db = openDb(dbPath);
    expect(db.findUserByEmail("old@example.com")).toMatchObject({
        id: "u1",
        totp_secret: null,
        totp_enabled_at: null,
    });
    expect(db.findRefreshToken("th")).toMatchObject({ mfa: 0 });
    db.close();
    // Opening again doesn't try to add them twice.
    openDb(dbPath).close();
});

test("logs the schema migration at startup, once", async () => {
    const dbPath = join(mkdtempSync(join(tmpdir(), "auth-")), "auth.sqlite");
    const first = await setup({ dbPath });
    expect(first.find("database migrated")).toMatchObject([{ from: 0, to: 2 }]);

    const again = await setup({ dbPath });
    expect(again.find("database migrated")).toEqual([]);
});
