import { generateMfaKey } from "../src/mfa";

// Prints a fresh key for encrypting TOTP secrets as a line for .env:
//   bun run gen-mfa-key >> .env
// Keep it as safe as AUTH_PRIVATE_KEY. Losing it turns MFA off for everyone
// in practice: stored secrets can't be decrypted, so nobody can pass the
// second step until an admin runs `bun run reset-mfa`.
if (import.meta.main) {
    console.log(`MFA_ENCRYPTION_KEY=${generateMfaKey()}`);
}
