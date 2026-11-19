import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "./db";
import { MIGRATIONS, migrate } from "./migrate";

const tempPath = () =>
    join(mkdtempSync(join(tmpdir(), "auth-migrate-")), "auth.sqlite");

const version = (db: Database) =>
    db.query<{ user_version: number }, []>("PRAGMA user_version").get()
        ?.user_version;

const columns = (db: Database, table: string) =>
    db
        .query<{ name: string }, []>(`PRAGMA table_info(${table})`)
        .all()
        .map((c) => c.name);

// The schema as it was before migrations existed, optionally with what the
// MFA release added through its addColumn helper.
function legacyDb(path: string, { withMfa = false } = {}) {
    const db = new Database(path);
    db.run(`CREATE TABLE users (
        id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL, created_at INTEGER NOT NULL)`);
    db.run(`CREATE TABLE refresh_tokens (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
        revoked_at INTEGER)`);
    if (withMfa) {
        db.run("ALTER TABLE users ADD COLUMN totp_secret TEXT");
        db.run("ALTER TABLE users ADD COLUMN totp_enabled_at INTEGER");
        db.run("ALTER TABLE users ADD COLUMN totp_last_step INTEGER");
        db.run(
            "ALTER TABLE refresh_tokens ADD COLUMN mfa INTEGER NOT NULL DEFAULT 0",
        );
        db.run(`CREATE TABLE recovery_codes (id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash TEXT NOT NULL, used_at INTEGER)`);
    }
    db.run(
        "INSERT INTO users (id, email, password_hash, created_at) VALUES ('u1', 'old@example.com', 'hash', 1)",
    );
    db.close();
}

test("migrations are numbered 1, 2, 3… with no gaps", () => {
    expect(MIGRATIONS.map((m) => m.version)).toEqual(
        MIGRATIONS.map((_, i) => i + 1),
    );
});

test("a new database gets every migration", () => {
    const db = new Database(":memory:");
    expect(migrate(db)).toEqual({ from: 0, to: MIGRATIONS.length });
    expect(version(db)).toBe(MIGRATIONS.length);
    expect(columns(db, "users")).toContain("totp_secret");
    expect(columns(db, "refresh_tokens")).toContain("mfa");
    expect(columns(db, "recovery_codes")).toContain("code_hash");
});

test("running again does nothing", () => {
    const path = tempPath();
    openDb(path).close();
    const db = openDb(path);
    expect(db.migrated).toEqual({
        from: MIGRATIONS.length,
        to: MIGRATIONS.length,
    });
    db.close();
});

test("a database from before MFA is adopted at 1 and upgraded, keeping its data", () => {
    const path = tempPath();
    legacyDb(path);

    const db = openDb(path);
    expect(db.migrated).toEqual({ from: 1, to: 2 });
    expect(db.findUserByEmail("old@example.com")).toMatchObject({
        id: "u1",
        totp_secret: null,
    });
    db.close();
});

test("a database from the MFA release is adopted at 2 without changes", () => {
    const path = tempPath();
    legacyDb(path, { withMfa: true });

    const db = openDb(path);
    expect(db.migrated).toEqual({ from: 2, to: 2 });
    expect(db.findUserByEmail("old@example.com")?.id).toBe("u1");
    db.close();
});

test("a database with only part of the MFA schema is refused", () => {
    const path = tempPath();
    legacyDb(path);
    const raw = new Database(path);
    raw.run("ALTER TABLE users ADD COLUMN totp_secret TEXT");
    raw.close();

    expect(() => openDb(path)).toThrow("only part of the MFA schema");
});

test("a failing migration rolls back and leaves the version alone", () => {
    const db = new Database(":memory:");
    const [first] = MIGRATIONS;
    if (!first) throw new Error("no migrations");
    const broken = {
        version: 2,
        name: "broken",
        sql: "CREATE TABLE half_done (x INTEGER); SELECT * FROM no_such_table;",
    };

    expect(() => migrate(db, [first, broken])).toThrow();
    expect(version(db)).toBe(1);
    expect(
        db.query("SELECT 1 FROM sqlite_master WHERE name = 'half_done'").get(),
    ).toBeNull();

    // Fixed migration: runs from where it stopped.
    expect(
        migrate(db, [first, { ...broken, sql: "CREATE TABLE half_done (x)" }]),
    ).toEqual({ from: 1, to: 2 });
});

test("a database newer than this build is refused", () => {
    const db = new Database(":memory:");
    migrate(db);
    db.run(`PRAGMA user_version = ${MIGRATIONS.length + 1}`);
    expect(() => migrate(db)).toThrow("Run a newer auth_service");
});
