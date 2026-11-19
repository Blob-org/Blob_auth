import { Database } from "bun:sqlite";
import { migrate } from "./migrate";

export type User = {
    id: string;
    email: string;
    password_hash: string;
    // Encrypted (see mfa.ts). Set but not enabled while setup is unconfirmed.
    totp_secret: string | null;
    totp_enabled_at: number | null;
    // The last 30-second TOTP step accepted, so a code can't be used twice.
    totp_last_step: number | null;
};

export type RefreshToken = {
    id: string;
    user_id: string;
    expires_at: number;
    revoked_at: number | null;
    // 1 when the session was opened with a second factor.
    mfa: number;
};

const USER_COLUMNS =
    "id, email, password_hash, totp_secret, totp_enabled_at, totp_last_step";

export function openDb(path: string) {
    const db = new Database(path, { create: true, strict: true });
    db.run("PRAGMA journal_mode = WAL");
    db.run("PRAGMA foreign_keys = ON");
    // Creates or upgrades the schema (src/migrations/*.sql).
    const migrated = migrate(db);

    return {
        // Schema versions before and after opening, for the startup log.
        migrated,

        createUser(email: string, passwordHash: string): User {
            const user = {
                id: crypto.randomUUID(),
                email,
                password_hash: passwordHash,
            };
            db.query(
                "INSERT INTO users (id, email, password_hash, created_at) VALUES ($id, $email, $password_hash, $now)",
            ).run({ ...user, now: Date.now() });
            return {
                ...user,
                totp_secret: null,
                totp_enabled_at: null,
                totp_last_step: null,
            };
        },

        findUserByEmail(email: string) {
            return db
                .query<User, [string]>(
                    `SELECT ${USER_COLUMNS} FROM users WHERE email = ?`,
                )
                .get(email);
        },

        findUserById(id: string) {
            return db
                .query<User, [string]>(
                    `SELECT ${USER_COLUMNS} FROM users WHERE id = ?`,
                )
                .get(id);
        },

        insertRefreshToken(
            userId: string,
            tokenHash: string,
            expiresAt: number,
            mfa: boolean,
        ) {
            db.query(
                "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, mfa) VALUES (?, ?, ?, ?, ?)",
            ).run(
                crypto.randomUUID(),
                userId,
                tokenHash,
                expiresAt,
                mfa ? 1 : 0,
            );
        },

        findRefreshToken(tokenHash: string) {
            return db
                .query<RefreshToken, [string]>(
                    "SELECT id, user_id, expires_at, revoked_at, mfa FROM refresh_tokens WHERE token_hash = ?",
                )
                .get(tokenHash);
        },

        revokeRefreshToken(id: string) {
            db.query(
                "UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            ).run(Date.now(), id);
        },

        revokeAllForUser(userId: string) {
            db.query(
                "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            ).run(Date.now(), userId);
        },

        // Starts (or restarts) setup. MFA stays off until enableTotp.
        setTotpSecret(userId: string, encryptedSecret: string) {
            db.query(
                "UPDATE users SET totp_secret = ?, totp_enabled_at = NULL, totp_last_step = NULL WHERE id = ?",
            ).run(encryptedSecret, userId);
        },

        enableTotp(userId: string, step: number) {
            db.query(
                "UPDATE users SET totp_enabled_at = ?, totp_last_step = ? WHERE id = ?",
            ).run(Date.now(), step, userId);
        },

        disableTotp: db.transaction((userId: string) => {
            db.query(
                "UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = NULL WHERE id = ?",
            ).run(userId);
            db.query("DELETE FROM recovery_codes WHERE user_id = ?").run(
                userId,
            );
        }),

        // False when that step (or a later one) was already used, including
        // by a request racing this one.
        claimTotpStep(userId: string, step: number): boolean {
            const { changes } = db
                .query(
                    "UPDATE users SET totp_last_step = ? WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)",
                )
                .run(step, userId, step);
            return changes === 1;
        },

        replaceRecoveryCodes: db.transaction(
            (userId: string, codeHashes: string[]) => {
                db.query("DELETE FROM recovery_codes WHERE user_id = ?").run(
                    userId,
                );
                const insert = db.query(
                    "INSERT INTO recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)",
                );
                for (const hash of codeHashes) {
                    insert.run(crypto.randomUUID(), userId, hash);
                }
            },
        ),

        countUnusedRecoveryCodes(userId: string): number {
            return (
                db
                    .query<{ n: number }, [string]>(
                        "SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
                    )
                    .get(userId)?.n ?? 0
            );
        },

        // Marks the code used. False when it's wrong, someone else's, or
        // already used (including by a request racing this one).
        useRecoveryCode(userId: string, codeHash: string): boolean {
            const { changes } = db
                .query(
                    "UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
                )
                .run(Date.now(), userId, codeHash);
            return changes === 1;
        },

        // refresh_tokens and recovery_codes rows go with it (ON DELETE CASCADE).
        deleteUser(id: string) {
            db.query("DELETE FROM users WHERE id = ?").run(id);
        },

        close() {
            db.close();
        },
    };
}

export type Db = ReturnType<typeof openDb>;
