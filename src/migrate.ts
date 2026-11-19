import type { Database } from "bun:sqlite";
import init from "./migrations/001_init.sql" with { type: "text" };
import mfa from "./migrations/002_mfa.sql" with { type: "text" };

// Schema changes, applied in order. To change the schema, add the next
// numbered file in src/migrations/ and list it here. Never edit one that has
// been released: databases that already ran it won't run it again.
export type Migration = { version: number; name: string; sql: string };

export const MIGRATIONS: Migration[] = [
    { version: 1, name: "init", sql: init },
    { version: 2, name: "mfa", sql: mfa },
];

const hasTable = (db: Database, table: string) =>
    db
        .query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")
        .get(table) !== null;

const hasColumn = (db: Database, table: string, column: string) =>
    db
        .query<{ name: string }, []>(`PRAGMA table_info(${table})`)
        .all()
        .some((c) => c.name === column);

// Databases created before migrations existed have user_version 0 but
// already have tables. Work out which version their schema matches, so
// those migrations are skipped rather than failing on "table exists".
function adoptExisting(db: Database): number {
    if (!hasTable(db, "users")) return 0;
    const mfaParts = [
        hasColumn(db, "users", "totp_secret"),
        hasColumn(db, "users", "totp_enabled_at"),
        hasColumn(db, "users", "totp_last_step"),
        hasColumn(db, "refresh_tokens", "mfa"),
        hasTable(db, "recovery_codes"),
    ];
    if (mfaParts.every(Boolean)) return 2;
    if (!mfaParts.some(Boolean)) return 1;
    throw new Error(
        "The database has only part of the MFA schema, so its version can't be told. Restore a backup, or add the missing parts by hand and set PRAGMA user_version = 2.",
    );
}

// Brings the database up to the latest migration. Each migration and its
// version bump run in one transaction, so a failure leaves the database at
// the previous version. Returns the versions before and after.
export function migrate(
    db: Database,
    migrations: Migration[] = MIGRATIONS,
): { from: number; to: number } {
    let version = db
        .query<{ user_version: number }, []>("PRAGMA user_version")
        .get()?.user_version as number;
    if (version === 0) {
        version = adoptExisting(db);
        if (version > 0) db.run(`PRAGMA user_version = ${version}`);
    }
    const from = version;

    const latest = migrations.at(-1)?.version ?? 0;
    if (version > latest) {
        throw new Error(
            `The database schema is at version ${version}, but this build only knows up to ${latest}. Run a newer auth_service, or restore a backup.`,
        );
    }

    for (const migration of migrations) {
        if (migration.version <= version) continue;
        db.transaction(() => {
            db.run(migration.sql);
            db.run(`PRAGMA user_version = ${migration.version}`);
        })();
        version = migration.version;
    }
    return { from, to: version };
}
