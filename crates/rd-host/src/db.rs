//! SQLite store: users, roles/permissions, remembered devices, settings, audit log.
//!
//! * Passwords and PINs are stored as Argon2id hashes.
//! * "Remember this device" tokens are 256-bit random values; only their SHA-256 is stored.
//! * The very first account created is always an admin.
//! * Repeated failures lock an account for an increasing period (5 min, doubling, max 1 h).
//!   After [`PIN_DISABLE_AFTER`] failures in a row the PIN stops working until it is set
//!   again on the host, so a short PIN can't be worked through over the internet.
//!   Remembered devices (256-bit tokens) are not subject to lockouts, so a stranger
//!   guessing PINs can't lock the owner out of their own devices.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rd_core::proto::{Credential, DeviceInfo, Permissions, Role, UserInfo};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT NOT NULL,
    pin_hash        TEXT,
    role            TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    perm_view       INTEGER NOT NULL DEFAULT 1,
    perm_control    INTEGER NOT NULL DEFAULT 1,
    perm_clipboard  INTEGER NOT NULL DEFAULT 1,
    perm_files      INTEGER NOT NULL DEFAULT 0,
    disabled        INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    last_used   TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY,
    ts       TEXT NOT NULL DEFAULT (datetime('now')),
    username TEXT,
    peer     TEXT,
    event    TEXT NOT NULL
);
"#;

pub const MAX_FAILURES: i64 = 5;
/// Consecutive failures after which the PIN is switched off.
pub const PIN_DISABLE_AFTER: i64 = 10;
pub const MIN_PASSWORD_LEN: usize = 8;

pub struct Db {
    conn: Connection,
}

/// Why a login failed. The client only ever sees a generic message, except for lockouts.
#[derive(Debug)]
pub enum AuthError {
    Invalid,
    Locked(i64),
    Disabled,
    /// Too many wrong PINs; the PIN must be set again on the host.
    PinDisabled,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Invalid => f.write_str("invalid username or credentials"),
            AuthError::Locked(secs) => write!(f, "too many failed attempts; account locked for {} more minute(s)", (secs + 59) / 60),
            AuthError::Disabled => f.write_str("account disabled"),
            AuthError::PinDisabled => f.write_str(
                "the PIN was switched off after too many wrong tries; set a new PIN on that computer",
            ),
        }
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn hash_secret(secret: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash: {e}"))?
        .to_string())
}

fn verify_secret(secret: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(secret.as_bytes(), &h).is_ok())
}

fn token_hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn random_token() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    hex(&b)
}

pub fn validate_username(u: &str) -> Result<()> {
    if u.is_empty() || u.len() > 64 || !u.chars().all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c)) {
        bail!("username must be 1-64 characters of letters, digits, '.', '_', '-', '@'");
    }
    Ok(())
}

pub fn validate_password(p: &str) -> Result<()> {
    if p.chars().count() < MIN_PASSWORD_LEN {
        bail!("password must be at least {MIN_PASSWORD_LEN} characters");
    }
    Ok(())
}

pub fn validate_pin(p: &str) -> Result<()> {
    if !(4..=12).contains(&p.len()) || !p.chars().all(|c| c.is_ascii_digit()) {
        bail!("PIN must be 4-12 digits");
    }
    Ok(())
}

impl Db {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let conn = Connection::open(dir.join("rd-host.db")).context("open database")?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;")?;
        conn.execute_batch(SCHEMA).context("create schema")?;
        // v1 -> v2: clipboard / file-transfer permissions. Existing accounts get clipboard
        // only if they could already control the machine, and no file access, so an
        // upgrade never widens what a view-only account can do.
        for (col, copy_from) in [("perm_clipboard", Some("perm_control")), ("perm_files", None)] {
            let exists: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('users') WHERE name = ?1",
                [col],
                |r| r.get(0),
            )?;
            if !exists {
                conn.execute_batch(&format!("ALTER TABLE users ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0"))?;
                if let Some(src) = copy_from {
                    conn.execute_batch(&format!("UPDATE users SET {col} = {src}"))?;
                }
            }
        }
        Ok(Self { conn })
    }

    // ------------------------------------------------------------ settings

    pub fn setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0)).optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------ users

    pub fn user_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?)
    }

    /// Create a user. If this is the first account it is forced to admin with full rights.
    /// Returns the role actually assigned.
    pub fn create_user(&mut self, username: &str, password: &str, role: Role, perms: Permissions) -> Result<Role> {
        validate_username(username)?;
        validate_password(password)?;
        let hash = hash_secret(password)?;
        let tx = self.conn.transaction()?;
        let first: bool = tx.query_row("SELECT COUNT(*) = 0 FROM users", [], |r| r.get(0))?;
        let (role, perms) = if first { (Role::Admin, Permissions::FULL) } else { (role, perms) };
        tx.execute(
            "INSERT INTO users(username, password_hash, role, perm_view, perm_control, perm_clipboard, perm_files)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![username, hash, role.as_str(), perms.view, perms.control, perms.clipboard, perms.files],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                anyhow::anyhow!("user '{username}' already exists")
            }
            e => e.into(),
        })?;
        tx.commit()?;
        Ok(role)
    }

    fn user_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<UserInfo> {
        let role: String = r.get("role")?;
        Ok(UserInfo {
            username: r.get("username")?,
            role: role.parse().unwrap_or(Role::User),
            perms: Permissions {
                view: r.get("perm_view")?,
                control: r.get("perm_control")?,
                clipboard: r.get("perm_clipboard")?,
                files: r.get("perm_files")?,
            },
            has_pin: r.get::<_, Option<String>>("pin_hash")?.is_some(),
            disabled: r.get("disabled")?,
        })
    }

    pub fn get_user(&self, username: &str) -> Result<Option<UserInfo>> {
        Ok(self.conn.query_row("SELECT * FROM users WHERE username = ?1", [username], Self::user_row).optional()?)
    }

    pub fn list_users(&self) -> Result<Vec<UserInfo>> {
        let mut st = self.conn.prepare("SELECT * FROM users ORDER BY id")?;
        let rows = st.query_map([], Self::user_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn require_user(&self, username: &str) -> Result<()> {
        if self.get_user(username)?.is_none() {
            bail!("no such user '{username}'");
        }
        Ok(())
    }

    fn admin_count_excluding(&self, username: &str) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND username <> ?1",
            [username],
            |r| r.get(0),
        )?)
    }

    fn guard_last_admin(&self, username: &str) -> Result<()> {
        let u = self.get_user(username)?;
        if u.is_some_and(|u| u.role == Role::Admin) && self.admin_count_excluding(username)? == 0 {
            bail!("'{username}' is the last active admin; create or promote another admin first");
        }
        Ok(())
    }

    pub fn remove_user(&self, username: &str) -> Result<()> {
        self.require_user(username)?;
        self.guard_last_admin(username)?;
        self.conn.execute("DELETE FROM users WHERE username = ?1", [username])?;
        Ok(())
    }

    pub fn set_role(&self, username: &str, role: Role) -> Result<()> {
        self.require_user(username)?;
        if role != Role::Admin {
            self.guard_last_admin(username)?;
        }
        self.conn.execute("UPDATE users SET role = ?2 WHERE username = ?1", params![username, role.as_str()])?;
        Ok(())
    }

    pub fn set_permissions(&self, username: &str, p: Permissions) -> Result<()> {
        self.require_user(username)?;
        self.conn.execute(
            "UPDATE users SET perm_view = ?2, perm_control = ?3, perm_clipboard = ?4, perm_files = ?5 WHERE username = ?1",
            params![username, p.view, p.control, p.clipboard, p.files],
        )?;
        Ok(())
    }

    pub fn set_disabled(&self, username: &str, disabled: bool) -> Result<()> {
        self.require_user(username)?;
        if disabled {
            self.guard_last_admin(username)?;
        }
        self.conn.execute("UPDATE users SET disabled = ?2 WHERE username = ?1", params![username, disabled])?;
        Ok(())
    }

    /// Changing a password also revokes that user's remembered devices.
    pub fn set_password(&self, username: &str, password: &str) -> Result<()> {
        self.require_user(username)?;
        validate_password(password)?;
        let hash = hash_secret(password)?;
        self.conn.execute(
            "UPDATE users SET password_hash = ?2, failed_attempts = 0, locked_until = NULL WHERE username = ?1",
            params![username, hash],
        )?;
        self.conn.execute(
            "DELETE FROM devices WHERE user_id = (SELECT id FROM users WHERE username = ?1)",
            [username],
        )?;
        Ok(())
    }

    pub fn set_pin(&self, username: &str, pin: Option<&str>) -> Result<()> {
        self.require_user(username)?;
        let hash = match pin {
            Some(p) => {
                validate_pin(p)?;
                Some(hash_secret(p)?)
            }
            None => None,
        };
        // A new PIN also clears any lockout, including a switched-off PIN.
        self.conn.execute(
            "UPDATE users SET pin_hash = ?2, failed_attempts = 0, locked_until = NULL WHERE username = ?1",
            params![username, hash],
        )?;
        Ok(())
    }

    pub fn unlock(&self, username: &str) -> Result<()> {
        self.require_user(username)?;
        self.conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?1", [username])?;
        Ok(())
    }

    // ------------------------------------------------------------ authentication

    pub fn authenticate(&self, username: &str, cred: &Credential) -> Result<Result<UserInfo, AuthError>> {
        struct Row {
            id: i64,
            password_hash: String,
            pin_hash: Option<String>,
            disabled: bool,
            failed: i64,
            locked_until: Option<i64>,
        }
        let row = self
            .conn
            .query_row(
                "SELECT id, password_hash, pin_hash, disabled, failed_attempts, locked_until FROM users WHERE username = ?1",
                [username],
                |r| {
                    Ok(Row {
                        id: r.get(0)?,
                        password_hash: r.get(1)?,
                        pin_hash: r.get(2)?,
                        disabled: r.get(3)?,
                        failed: r.get(4)?,
                        locked_until: r.get(5)?,
                    })
                },
            )
            .optional()?;
        let Some(row) = row else {
            // Burn comparable time so usernames can't be probed by timing.
            static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
            let dummy = DUMMY.get_or_init(|| hash_secret("dummy-password").unwrap_or_default());
            let _ = verify_secret("x", dummy);
            return Ok(Err(AuthError::Invalid));
        };
        if row.disabled {
            return Ok(Err(AuthError::Disabled));
        }
        let t = now();
        let is_token = matches!(cred, Credential::DeviceToken(_));
        if !is_token {
            if matches!(cred, Credential::Pin(_)) && row.failed >= PIN_DISABLE_AFTER {
                return Ok(Err(AuthError::PinDisabled));
            }
            if let Some(until) = row.locked_until.filter(|u| *u > t) {
                return Ok(Err(AuthError::Locked(until - t)));
            }
        }
        let ok = match cred {
            Credential::Password(p) => verify_secret(p, &row.password_hash),
            Credential::Pin(p) => row.pin_hash.as_deref().is_some_and(|h| verify_secret(p, h)),
            Credential::DeviceToken(tok) => {
                let n = self.conn.execute(
                    "UPDATE devices SET last_used = datetime('now') WHERE user_id = ?1 AND token_hash = ?2",
                    params![row.id, token_hash(tok)],
                )?;
                n == 1
            }
        };
        if !ok && is_token {
            // A wrong token is not a guess at the user's secret; don't count it.
            return Ok(Err(AuthError::Invalid));
        }
        if !ok {
            let failed = row.failed + 1;
            if matches!(cred, Credential::Pin(_)) && failed >= PIN_DISABLE_AFTER {
                self.conn.execute("UPDATE users SET failed_attempts = ?2 WHERE id = ?1", params![row.id, failed])?;
                return Ok(Err(AuthError::PinDisabled));
            }
            let lock = if failed >= MAX_FAILURES {
                let mins = (5i64 << (failed - MAX_FAILURES).min(4)).min(60);
                Some(t + mins * 60)
            } else {
                None
            };
            self.conn.execute(
                "UPDATE users SET failed_attempts = ?2, locked_until = ?3 WHERE id = ?1",
                params![row.id, failed, lock],
            )?;
            return Ok(Err(match lock {
                Some(until) => AuthError::Locked(until - t),
                None => AuthError::Invalid,
            }));
        }
        if !is_token {
            self.conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?1", [row.id])?;
        }
        Ok(Ok(self.get_user(username)?.expect("user exists")))
    }

    // ------------------------------------------------------------ devices

    /// Issue a "remember this device" token. Returns the plaintext token (shown once).
    pub fn add_device(&self, username: &str, name: &str) -> Result<String> {
        let token = random_token();
        let name: String = name.chars().take(100).collect();
        let n = self.conn.execute(
            "INSERT INTO devices(user_id, name, token_hash) SELECT id, ?2, ?3 FROM users WHERE username = ?1",
            params![username, name, token_hash(&token)],
        )?;
        if n != 1 {
            bail!("no such user '{username}'");
        }
        Ok(token)
    }

    pub fn list_devices(&self, only_user: Option<&str>) -> Result<Vec<DeviceInfo>> {
        let mut st = self.conn.prepare(
            "SELECT d.id, u.username, d.name, d.created_at, d.last_used FROM devices d JOIN users u ON u.id = d.user_id
             WHERE ?1 IS NULL OR u.username = ?1 ORDER BY d.id",
        )?;
        let rows = st.query_map([only_user], |r| {
            Ok(DeviceInfo { id: r.get(0)?, username: r.get(1)?, name: r.get(2)?, created: r.get(3)?, last_used: r.get(4)? })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Revoke a device; if `owner` is set the device must belong to that user.
    pub fn revoke_device(&self, id: i64, owner: Option<&str>) -> Result<()> {
        let n = self.conn.execute(
            "DELETE FROM devices WHERE id = ?1 AND (?2 IS NULL OR user_id = (SELECT id FROM users WHERE username = ?2))",
            params![id, owner],
        )?;
        if n == 0 {
            bail!("no such device {id}");
        }
        Ok(())
    }

    // ------------------------------------------------------------ audit

    pub fn audit(&self, username: Option<&str>, peer: &str, event: &str) {
        if let Err(e) =
            self.conn.execute("INSERT INTO audit(username, peer, event) VALUES (?1, ?2, ?3)", params![username, peer, event])
        {
            log::warn!("audit log write failed: {e}");
        }
    }

    pub fn recent_audit(&self, limit: u32) -> Result<Vec<(String, Option<String>, Option<String>, String)>> {
        let mut st = self.conn.prepare("SELECT ts, username, peer, event FROM audit ORDER BY id DESC LIMIT ?1")?;
        let rows = st.query_map([limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> (Db, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("rd-db-test-{}", random_token()));
        (Db::open(&dir).unwrap(), dir)
    }

    #[test]
    fn first_user_is_admin_and_auth_works() {
        let (mut db, dir) = tmp();
        let role = db.create_user("alice", "correct horse", Role::User, Permissions::VIEW_ONLY).unwrap();
        assert_eq!(role, Role::Admin, "first account must be admin");
        let role = db.create_user("bob", "battery staple", Role::User, Permissions::VIEW_ONLY).unwrap();
        assert_eq!(role, Role::User);
        assert!(db.create_user("BOB", "whatever123", Role::User, Permissions::FULL).is_err(), "case-insensitive unique");

        let ok = db.authenticate("alice", &Credential::Password("correct horse".into())).unwrap().unwrap();
        assert_eq!(ok.role, Role::Admin);
        assert!(db.authenticate("alice", &Credential::Password("nope".into())).unwrap().is_err());
        assert!(db.authenticate("nobody", &Credential::Password("x".into())).unwrap().is_err());

        // PIN + device token.
        db.set_pin("bob", Some("123456")).unwrap();
        assert!(db.authenticate("bob", &Credential::Pin("123456".into())).unwrap().is_ok());
        let tok = db.add_device("bob", "laptop").unwrap();
        assert!(db.authenticate("bob", &Credential::DeviceToken(tok.clone())).unwrap().is_ok());
        assert!(db.authenticate("alice", &Credential::DeviceToken(tok.clone())).unwrap().is_err(), "token bound to user");
        db.set_password("bob", "new password!").unwrap();
        assert!(db.authenticate("bob", &Credential::DeviceToken(tok)).unwrap().is_err(), "password change revokes devices");

        // Last admin protection.
        assert!(db.remove_user("alice").is_err());
        assert!(db.set_role("alice", Role::User).is_err());
        db.set_role("bob", Role::Admin).unwrap();
        db.set_role("alice", Role::User).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lockout_after_failures() {
        let (mut db, dir) = tmp();
        db.create_user("carol", "password123", Role::User, Permissions::FULL).unwrap();
        for _ in 0..MAX_FAILURES {
            let _ = db.authenticate("carol", &Credential::Password("bad".into())).unwrap();
        }
        let r = db.authenticate("carol", &Credential::Password("password123".into())).unwrap();
        assert!(matches!(r, Err(AuthError::Locked(_))), "correct password rejected while locked");
        db.unlock("carol").unwrap();
        assert!(db.authenticate("carol", &Credential::Password("password123".into())).unwrap().is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn short_pin_switches_off_and_devices_ignore_lockouts() {
        let (mut db, dir) = tmp();
        db.create_user("owner", "long random password", Role::Admin, Permissions::FULL).unwrap();
        db.set_pin("owner", Some("4821")).unwrap();
        assert!(db.set_pin("owner", Some("123")).is_err(), "3 digits is too short");
        let tok = db.add_device("owner", "laptop").unwrap();
        for i in 0..PIN_DISABLE_AFTER {
            // Skip the timed lockouts so every guess is counted.
            db.conn.execute("UPDATE users SET locked_until = NULL", []).unwrap();
            let r = db.authenticate("owner", &Credential::Pin(format!("{:04}", i))).unwrap();
            assert!(r.is_err());
            // A remembered device still works while the account is locked.
            assert!(db.authenticate("owner", &Credential::DeviceToken(tok.clone())).unwrap().is_ok());
            assert!(db.authenticate("owner", &Credential::DeviceToken("0".repeat(64))).unwrap().is_err());
        }
        db.conn.execute("UPDATE users SET locked_until = NULL", []).unwrap();
        let r = db.authenticate("owner", &Credential::Pin("4821".into())).unwrap();
        assert!(matches!(r, Err(AuthError::PinDisabled)), "right PIN refused once switched off: {r:?}");
        db.set_pin("owner", Some("4821")).unwrap();
        assert!(db.authenticate("owner", &Credential::Pin("4821".into())).unwrap().is_ok(), "setting it again re-enables it");
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn v1_database_upgrade_does_not_widen_view_only() {
        let dir = std::env::temp_dir().join(format!("rd-db-mig-{}", random_token()));
        std::fs::create_dir_all(&dir).unwrap();
        {
            let c = Connection::open(dir.join("rd-host.db")).unwrap();
            c.execute_batch(
                "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                 password_hash TEXT NOT NULL, pin_hash TEXT, role TEXT NOT NULL, perm_view INTEGER NOT NULL DEFAULT 1,
                 perm_control INTEGER NOT NULL DEFAULT 1, disabled INTEGER NOT NULL DEFAULT 0,
                 failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until INTEGER,
                 created_at TEXT NOT NULL DEFAULT (datetime('now')));
                 INSERT INTO users(username, password_hash, role, perm_view, perm_control) VALUES ('ctl', 'x', 'user', 1, 1);
                 INSERT INTO users(username, password_hash, role, perm_view, perm_control) VALUES ('look', 'x', 'user', 1, 0);",
            )
            .unwrap();
        }
        let db = Db::open(&dir).unwrap();
        let ctl = db.get_user("ctl").unwrap().unwrap().perms;
        let look = db.get_user("look").unwrap().unwrap().perms;
        assert!(ctl.clipboard && !ctl.files);
        assert!(!look.clipboard && !look.files && !look.control);
        drop(db);
        let _ = std::fs::remove_dir_all(dir);
    }
}
