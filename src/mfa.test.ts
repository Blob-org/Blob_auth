import { expect, test } from "bun:test";
import {
    createSecretBox,
    currentTotpCode,
    generateMfaKey,
    generateRecoveryCodes,
    looksLikeRecoveryCode,
    matchTotp,
    newTotpSecret,
    normalizeRecoveryCode,
    otpauthUrl,
} from "./mfa";

test("the secret box round-trips and uses a fresh IV each time", async () => {
    const box = await createSecretBox(generateMfaKey());
    const a = await box.encrypt("JBSWY3DPEHPK3PXP");
    const b = await box.encrypt("JBSWY3DPEHPK3PXP");

    expect(a).not.toBe(b);
    expect(a).not.toContain("JBSWY3DPEHPK3PXP");
    expect(await box.decrypt(a)).toBe("JBSWY3DPEHPK3PXP");
    expect(await box.decrypt(b)).toBe("JBSWY3DPEHPK3PXP");
});

test("a secret can't be read with another key or after tampering", async () => {
    const box = await createSecretBox(generateMfaKey());
    const other = await createSecretBox(generateMfaKey());
    const stored = await box.encrypt("JBSWY3DPEHPK3PXP");

    await expect(other.decrypt(stored)).rejects.toThrow();
    const [iv, ciphertext = ""] = stored.split(".");
    const flipped = `${iv}.${ciphertext.startsWith("A") ? "B" : "A"}${ciphertext.slice(1)}`;
    await expect(box.decrypt(flipped)).rejects.toThrow();
});

test("the key must be 32 bytes", async () => {
    await expect(createSecretBox("too-short")).rejects.toThrow(
        "MFA_ENCRYPTION_KEY",
    );
});

test("matchTotp accepts the previous, current and next window only", () => {
    const secret = newTotpSecret();
    const now = 1_700_000_015_000; // 15 s into a 30 s window
    const step = Math.floor(now / 30_000);

    expect(matchTotp(secret, currentTotpCode(secret, now), now)).toBe(step);
    expect(matchTotp(secret, currentTotpCode(secret, now - 30_000), now)).toBe(
        step - 1,
    );
    expect(matchTotp(secret, currentTotpCode(secret, now + 30_000), now)).toBe(
        step + 1,
    );
    expect(
        matchTotp(secret, currentTotpCode(secret, now - 60_000), now),
    ).toBeNull();
    expect(
        matchTotp(secret, currentTotpCode(secret, now + 60_000), now),
    ).toBeNull();
});

test("matchTotp ignores spaces and rejects anything but 6 digits", () => {
    const secret = newTotpSecret();
    const now = 1_700_000_015_000;
    const code = currentTotpCode(secret, now);

    expect(
        matchTotp(secret, `${code.slice(0, 3)} ${code.slice(3)}`, now),
    ).not.toBeNull();
    expect(matchTotp(secret, "", now)).toBeNull();
    expect(matchTotp(secret, "12345", now)).toBeNull();
    expect(matchTotp(secret, "abcdef", now)).toBeNull();
});

test("the otpauth link names the issuer and the account", () => {
    const url = new URL(
        otpauthUrl("JBSWY3DPEHPK3PXP", "a@example.com", "Blob storage"),
    );
    expect(url.protocol).toBe("otpauth:");
    expect(url.host).toBe("totp");
    expect(decodeURIComponent(url.pathname)).toBe(
        "/Blob storage:a@example.com",
    );
    expect(url.searchParams.get("secret")).toBe("JBSWY3DPEHPK3PXP");
    expect(url.searchParams.get("issuer")).toBe("Blob storage");
});

test("recovery codes are 10 distinct xxxxx-xxxxx base32 codes", () => {
    const codes = generateRecoveryCodes();
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    for (const code of codes) {
        expect(code).toMatch(/^[a-z2-7]{5}-[a-z2-7]{5}$/);
        expect(looksLikeRecoveryCode(code)).toBe(true);
    }
});

test("recovery codes compare without case, spaces or dashes", () => {
    expect(normalizeRecoveryCode("ABCDE FGHIJ")).toBe("abcdefghij");
    expect(normalizeRecoveryCode("abcde-fghij")).toBe("abcdefghij");
    expect(looksLikeRecoveryCode("123456")).toBe(false);
});

test("recovery code hashes are keyed and ignore case, spaces and dashes", async () => {
    const box = await createSecretBox(generateMfaKey());
    const other = await createSecretBox(generateMfaKey());
    const hash = await box.hashRecoveryCode("abcde-fghij");

    expect(await box.hashRecoveryCode("ABCDE FGHIJ")).toBe(hash);
    expect(await box.hashRecoveryCode("abcde-fghik")).not.toBe(hash);
    expect(await other.hashRecoveryCode("abcde-fghij")).not.toBe(hash);
});
