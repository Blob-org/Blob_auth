import { join } from "node:path";
import { openDb } from "../src/db";
import { createLogger } from "../src/log";

// Turns MFA off for a user who lost both their authenticator and their
// recovery codes, and signs them out everywhere. Check who's asking first
// (see the "MFA lockout" runbook in blob_docs).
//   bun run reset-mfa <email>
//   docker compose exec auth bun run reset-mfa <email>
export function resetMfa(dbPath: string, email: string) {
    const db = openDb(dbPath);
    try {
        const user = db.findUserByEmail(email.trim().toLowerCase());
        if (!user) return null;
        db.disableTotp(user.id);
        db.revokeAllForUser(user.id);
        return user.id;
    } finally {
        db.close();
    }
}

if (import.meta.main) {
    const email = process.argv[2];
    if (!email) {
        console.error("Usage: bun run reset-mfa <email>");
        process.exit(2);
    }
    const dbPath =
        process.env.DB_PATH ?? join(import.meta.dir, "..", "auth.sqlite");
    const userId = resetMfa(dbPath, email);
    if (!userId) {
        console.error("No user with that email.");
        process.exit(1);
    }
    createLogger({ service: "auth" }).warn("mfa reset by admin", { userId });
}
