use rusqlite::{Connection, Result as SqlResult, params, Row};
use std::path::Path;

pub struct Database {
    pub path: String,
}

#[derive(Debug)]
pub struct PasswordEntry {
    pub encrypted_name: Vec<u8>, 
    pub encrypted_username: Vec<u8>,
    pub encrypted_password: Vec<u8>,
    pub encrypted_url: Vec<u8>,
    pub nonce: Vec<u8>,
    pub shared_secret: Vec<u8>,
    pub created_at: String,
    pub search_hash: String,
}

#[derive(Debug)]
pub struct MasterPasswordEntry {
    pub password_hash: String,
    pub public_key: Vec<u8>,
    pub salt: String,
}

#[derive(Debug)]
pub struct TotpEntry {
    pub encrypted_service_name: Vec<u8>,
    pub encrypted_secret: Vec<u8>,
    pub encrypted_issuer: Vec<u8>,
    pub algorithm: String,              // SHA1, SHA256, SHA512
    pub digits: u32,                    // 6 or 8
    pub period: u32,                    // Usually 30 seconds
    pub nonce: Vec<u8>,
    pub shared_secret: Vec<u8>,
    pub created_at: String,
    pub search_hash: String,
}

impl Database {
    pub fn new(path: String) -> Self {
        Self { path }
    }

    /// Initializes the database with required tables
    pub fn initialize(&self) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                encrypted_name BLOB NOT NULL,
                encrypted_username BLOB,
                encrypted_password BLOB NOT NULL,
                encrypted_url BLOB,
                nonce BLOB NOT NULL,
                shared_secret BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                search_hash TEXT NOT NULL UNIQUE
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS master (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL,
                public_key BLOB NOT NULL,
                salt TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS totp_secrets (
                id INTEGER PRIMARY KEY,
                encrypted_service_name BLOB NOT NULL,
                encrypted_secret BLOB NOT NULL,
                encrypted_issuer BLOB,
                algorithm TEXT DEFAULT 'SHA1',
                digits INTEGER DEFAULT 6,
                period INTEGER DEFAULT 30,
                nonce BLOB NOT NULL,
                shared_secret BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                search_hash TEXT NOT NULL UNIQUE
            )",
            [],
        )?;

        Ok(())
    }

    /// Checks if the database has already been initialized
    pub fn is_initialized(&self) -> bool {
        Path::new(&self.path).exists()
    }

    /// Stores the master password and public key
    pub fn store_master_password(&self, entry: &MasterPasswordEntry) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;
        conn.execute(
            "INSERT OR REPLACE INTO master (id, password_hash, public_key, salt) VALUES (1, ?1, ?2, ?3)",
            params![entry.password_hash, entry.public_key, entry.salt],
        )?;
        Ok(())
    }

    /// Loads the master password and public key
    pub fn load_master_password(&self) -> SqlResult<MasterPasswordEntry> {
        let conn = Connection::open(&self.path)?;
        let mut stmt = conn.prepare("SELECT password_hash, public_key, salt FROM master WHERE id = 1")?;
        
        stmt.query_row([], |row: &Row| {
            Ok(MasterPasswordEntry {
                password_hash: row.get(0)?,
                public_key: row.get(1)?,
                salt: row.get(2)?,
            })
        })
    }

    /// Stores a password entry (all metadata now encrypted)
    pub fn store_password(&self, entry: &PasswordEntry) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;
        conn.execute(
            "INSERT OR REPLACE INTO passwords (encrypted_name, encrypted_username, encrypted_password, encrypted_url, nonce, shared_secret, search_hash) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.encrypted_name,
                entry.encrypted_username,
                entry.encrypted_password,
                entry.encrypted_url,
                entry.nonce,
                entry.shared_secret,
                entry.search_hash,
            ],
        )?;
        Ok(())
    }

    /// Loads a password entry by search hash (derived from name)
    pub fn load_password(&self, search_hash: &str) -> SqlResult<PasswordEntry> {
        let conn = Connection::open(&self.path)?;
        let mut stmt = conn.prepare(
            "SELECT encrypted_name, encrypted_username, encrypted_password, encrypted_url, nonce, shared_secret, created_at, search_hash
             FROM passwords WHERE search_hash = ?1"
        )?;
        
        stmt.query_row([search_hash], |row: &Row| {
            Ok(PasswordEntry {
                encrypted_name: row.get(0)?,
                encrypted_username: row.get(1)?,
                encrypted_password: row.get(2)?,
                encrypted_url: row.get(3)?,
                nonce: row.get(4)?,
                shared_secret: row.get(5)?,
                created_at: row.get(6)?,
                search_hash: row.get(7)?,
            })
        })
    }

    /// Lists all password entries (returns encrypted entries for decryption by caller)
    pub fn list_passwords(&self) -> SqlResult<Vec<PasswordEntry>> {
        let conn = Connection::open(&self.path)?;
        let mut stmt = conn.prepare(
            "SELECT encrypted_name, encrypted_username, encrypted_password, encrypted_url, nonce, shared_secret, created_at, search_hash 
             FROM passwords ORDER BY created_at DESC"
        )?;
        
        let rows = stmt.query_map([], |row| {
            Ok(PasswordEntry {
                encrypted_name: row.get(0)?,
                encrypted_username: row.get(1)?,
                encrypted_password: row.get(2)?,
                encrypted_url: row.get(3)?,
                nonce: row.get(4)?,
                shared_secret: row.get(5)?,
                created_at: row.get(6)?,
                search_hash: row.get(7)?,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Deletes a password entry by search hash
    pub fn delete_password(&self, search_hash: &str) -> SqlResult<usize> {
        let conn = Connection::open(&self.path)?;
        let changed = conn.execute("DELETE FROM passwords WHERE search_hash = ?1", [search_hash])?;
        Ok(changed)
    }

    /// Stores a TOTP entry
    pub fn store_totp(&self, entry: &TotpEntry) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;
        conn.execute(
            "INSERT OR REPLACE INTO totp_secrets (encrypted_service_name, encrypted_secret, encrypted_issuer, algorithm, digits, period, nonce, shared_secret, search_hash) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.encrypted_service_name,
                entry.encrypted_secret,
                entry.encrypted_issuer,
                entry.algorithm,
                entry.digits,
                entry.period,
                entry.nonce,
                entry.shared_secret,
                entry.search_hash,
            ],
        )?;
        Ok(())
    }

    /// Loads a TOTP entry by search hash
    pub fn load_totp(&self, search_hash: &str) -> SqlResult<TotpEntry> {
        let conn = Connection::open(&self.path)?;
        let mut stmt = conn.prepare(
            "SELECT encrypted_service_name, encrypted_secret, encrypted_issuer, algorithm, digits, period, nonce, shared_secret, created_at, search_hash
             FROM totp_secrets WHERE search_hash = ?1"
        )?;
        
        stmt.query_row([search_hash], |row: &Row| {
            Ok(TotpEntry {
                encrypted_service_name: row.get(0)?,
                encrypted_secret: row.get(1)?,
                encrypted_issuer: row.get(2)?,
                algorithm: row.get(3)?,
                digits: row.get(4)?,
                period: row.get(5)?,
                nonce: row.get(6)?,
                shared_secret: row.get(7)?,
                created_at: row.get(8)?,
                search_hash: row.get(9)?,
            })
        })
    }

    /// Lists all TOTP entries
    pub fn list_totp(&self) -> SqlResult<Vec<TotpEntry>> {
        let conn = Connection::open(&self.path)?;
        let mut stmt = conn.prepare(
            "SELECT encrypted_service_name, encrypted_secret, encrypted_issuer, algorithm, digits, period, nonce, shared_secret, created_at, search_hash
             FROM totp_secrets ORDER BY created_at DESC"
        )?;
        
        let rows = stmt.query_map([], |row| {
            Ok(TotpEntry {
                encrypted_service_name: row.get(0)?,
                encrypted_secret: row.get(1)?,
                encrypted_issuer: row.get(2)?,
                algorithm: row.get(3)?,
                digits: row.get(4)?,
                period: row.get(5)?,
                nonce: row.get(6)?,
                shared_secret: row.get(7)?,
                created_at: row.get(8)?,
                search_hash: row.get(9)?,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Deletes a TOTP entry by search hash
    pub fn delete_totp(&self, search_hash: &str) -> SqlResult<usize> {
        let conn = Connection::open(&self.path)?;
        let changed = conn.execute("DELETE FROM totp_secrets WHERE search_hash = ?1", [search_hash])?;
        Ok(changed)
    }
}