import { Database } from "bun:sqlite";

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
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS refresh_tokens (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS recovery_codes (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash TEXT NOT NULL,
        used_at INTEGER
    )`);
    db.run(
        "CREATE INDEX IF NOT EXISTS recovery_codes_user ON recovery_codes (user_id, code_hash)",
    );

    // CREATE TABLE IF NOT EXISTS leaves existing tables alone, so columns
    // added later are added here when a database predates them.
    function addColumn(table: string, column: string, definition: string) {
        const columns = db
            .query<{ name: string }, []>(`PRAGMA table_info(${table})`)
            .all();
        if (!columns.some((c) => c.name === column)) {
            db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
        }
    }
    addColumn("users", "totp_secret", "TEXT");
    addColumn("users", "totp_enabled_at", "INTEGER");
    addColumn("users", "totp_last_step", "INTEGER");
    addColumn("refresh_tokens", "mfa", "INTEGER NOT NULL DEFAULT 0");

    return {
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
