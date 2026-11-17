import { Secret, TOTP } from "otpauth";

// TOTP as authenticator apps expect it (RFC 6238 defaults): SHA-1, 6 digits,
// a new code every 30 seconds.
const PERIOD_SECONDS = 30;
// Codes from the previous and next 30 seconds are accepted too, for phones
// whose clock is a little off.
const WINDOW = 1;
const RECOVERY_CODE_COUNT = 10;
const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

// Everything secret about MFA is keyed by MFA_ENCRYPTION_KEY, so a copy of
// the SQLite file alone doesn't let anyone generate a user's codes or test
// recovery codes offline. Two keys are derived from it with HKDF:
// - AES-256-GCM for TOTP secrets, with a random IV per secret, stored as
//   "<iv>.<ciphertext>" in base64url;
// - HMAC-SHA-256 for recovery codes. They're random (50 bits), so a keyed
//   hash is enough, and unlike a password hash it's fast and can be looked
//   up directly, so a wrong code costs one query, not ten slow hashes.
export type SecretBox = {
    encrypt(plaintext: string): Promise<string>;
    decrypt(stored: string): Promise<string>;
    hashRecoveryCode(code: string): Promise<string>;
};

export async function createSecretBox(
    keyBase64url: string,
): Promise<SecretBox> {
    const raw = Buffer.from(keyBase64url, "base64url");
    if (raw.length !== 32) {
        throw new Error(
            "MFA_ENCRYPTION_KEY must be 32 bytes, base64url-encoded. Run `bun run gen-mfa-key >> .env`.",
        );
    }
    const master = await crypto.subtle.importKey("raw", raw, "HKDF", false, [
        "deriveKey",
    ]);
    const derive = (
        info: string,
        algorithm: AesKeyGenParams | HmacKeyGenParams,
        usages: KeyUsage[],
    ) =>
        crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: new Uint8Array(0),
                info: new TextEncoder().encode(info),
            },
            master,
            algorithm,
            false,
            usages,
        );
    const aes = await derive(
        "auth_service totp secret",
        { name: "AES-GCM", length: 256 },
        ["encrypt", "decrypt"],
    );
    const hmac = await derive(
        "auth_service recovery code",
        { name: "HMAC", hash: "SHA-256", length: 256 },
        ["sign"],
    );

    return {
        async encrypt(plaintext) {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                aes,
                new TextEncoder().encode(plaintext),
            );
            return `${Buffer.from(iv).toString("base64url")}.${Buffer.from(ciphertext).toString("base64url")}`;
        },
        async decrypt(stored) {
            const [iv = "", ciphertext = ""] = stored.split(".");
            const plaintext = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: Buffer.from(iv, "base64url") },
                aes,
                Buffer.from(ciphertext, "base64url"),
            );
            return new TextDecoder().decode(plaintext);
        },
        async hashRecoveryCode(code) {
            const mac = await crypto.subtle.sign(
                "HMAC",
                hmac,
                new TextEncoder().encode(normalizeRecoveryCode(code)),
            );
            return Buffer.from(mac).toString("base64url");
        },
    };
}

export function generateMfaKey(): string {
    return Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString(
        "base64url",
    );
}

// A new base32 TOTP secret (160 bits, as RFC 4226 recommends).
export function newTotpSecret(): string {
    return new Secret({ size: 20 }).base32;
}

function totp(secret: string, label = "", issuer = "") {
    return new TOTP({
        issuer,
        label,
        secret: Secret.fromBase32(secret),
        period: PERIOD_SECONDS,
    });
}

// The otpauth:// link an authenticator app reads from the QR code.
export function otpauthUrl(secret: string, email: string, issuer: string) {
    return totp(secret, email, issuer).toString();
}

export function currentTotpCode(secret: string, now = Date.now()) {
    return totp(secret).generate({ timestamp: now });
}

// The 30-second step the code belongs to, or null if it's wrong. The caller
// still has to reject a step that was already used.
export function matchTotp(
    secret: string,
    code: string,
    now = Date.now(),
): number | null {
    const token = code.replace(/\s/g, "");
    if (!/^\d{6}$/.test(token)) return null;
    const delta = totp(secret).validate({
        token,
        timestamp: now,
        window: WINDOW,
    });
    if (delta === null) return null;
    return Math.floor(now / 1000 / PERIOD_SECONDS) + delta;
}

// One-time codes for when the phone is lost: "abcde-fghij", 50 random bits
// each. Only their hashes are stored.
export function generateRecoveryCodes(): string[] {
    return Array.from({ length: RECOVERY_CODE_COUNT }, () => {
        const bytes = crypto.getRandomValues(new Uint8Array(10));
        const chars = Array.from(bytes, (b) => BASE32[b & 31]).join("");
        return `${chars.slice(0, 5)}-${chars.slice(5)}`;
    });
}

// Recovery codes are compared without case, spaces or dashes, so
// "ABCDE FGHIJ" matches "abcde-fghij".
export function normalizeRecoveryCode(code: string): string {
    return code.toLowerCase().replace(/[\s-]/g, "");
}

export function looksLikeRecoveryCode(code: string): boolean {
    return /^[a-z2-7]{10}$/.test(normalizeRecoveryCode(code));
}
