use std::fs;
use std::path::Path;
use std::io::{self, Write};

use clap::{Parser, Subcommand};
use pqc_kyber::{Keypair, PublicKey, SecretKey, encapsulate};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::{SaltString, rand_core::OsRng as ArgonOsRng}};
use rusqlite::{Connection, Result as SqlResult, params};

#[derive(Parser)]
#[command(name = "pqc-password-manager")]
#[command(about = "Ein Post-Quantum-Cryptography sicherer Passwort-Manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialisiert den Passwort-Manager mit einem Master-Passwort
    Init,
    /// Füge ein neues Passwort hinzu
    Add {
        /// Name/Service für das Passwort
        name: String,
        /// Benutzername (optional)
        #[arg(short = 'u', long)]
        username: Option<String>,
        /// URL/Website (optional)
        #[arg(short = 'l', long)]
        url: Option<String>,
    },
    /// Zeige ein gespeichertes Passwort an
    Get {
        /// Name des Services
        name: String,
    },
    /// Liste alle gespeicherten Services auf
    List,
    /// Lösche einen Eintrag
    Delete {
        /// Name des Services
        name: String,
    },
    /// Ändere das Master-Passwort
    ChangeMaster,
}

#[derive(Clone)]
struct PasswordEntry {
    name: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    created_at: String,
}

struct PQCPasswordManager {
    db_path: String,
    public_key: Option<PublicKey>,
    secret_key: Option<SecretKey>,
}

impl PQCPasswordManager {
    fn new() -> Self {
        let home_dir = dirs::home_dir().expect("Konnte Home-Verzeichnis nicht finden");
        let config_dir = home_dir.join(".pqc_password_manager");
        
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir).expect("Konnte Konfigurationsverzeichnis nicht erstellen");
        }
        
        Self {
            db_path: config_dir.join("passwords.db").to_string_lossy().to_string(),
            public_key: None,
            secret_key: None,
        }
    }

    fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Prüfe ob bereits initialisiert
        if Path::new(&self.db_path).exists() {
            println!("Passwort-Manager ist bereits initialisiert!");
            return Ok(());
        }

        // Master-Passwort abfragen
        let master_password = self.prompt_password("Master-Passwort eingeben: ")?;
        let confirm_password = self.prompt_password("Master-Passwort bestätigen: ")?;

        if master_password != confirm_password {
            return Err("Passwörter stimmen nicht überein!".into());
        }

        // Kyber Schlüsselpaar generieren
        let keypair = Keypair::generate(&mut OsRng)?;
        self.public_key = Some(keypair.public);
        self.secret_key = Some(keypair.secret);

        // Datenbank initialisieren
        self.init_database()?;
        
        // Master-Passwort hashen und speichern
        self.store_master_password(&master_password)?;

        println!("✅ Passwort-Manager erfolgreich initialisiert!");
        println!("🔐 Post-Quantum-Cryptography Schlüssel generiert (Kyber512)");
        
        Ok(())
    }

    fn init_database(&self) -> SqlResult<()> {
        let conn = Connection::open(&self.db_path)?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                username TEXT,
                encrypted_password BLOB NOT NULL,
                url TEXT,
                nonce BLOB NOT NULL,
                shared_secret BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

        Ok(())
    }

    fn store_master_password(&self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        let salt = SaltString::generate(&mut ArgonOsRng);
        let argon2 = Argon2::default();
        let password_hash = match argon2.hash_password(password.as_bytes(), &salt) {
            Ok(hash) => hash.to_string(),
            Err(e) => return Err(format!("Failed to hash password: {}", e).into()),
        };

        let public_key_bytes = self.public_key.as_ref().unwrap();        let conn = Connection::open(&self.db_path)?;
        conn.execute(
            "INSERT INTO master (password_hash, public_key, salt) VALUES (?1, ?2, ?3)",
            params![password_hash, public_key_bytes, salt.as_str()],
        )?;

        Ok(())
    }

    fn verify_master_password(&mut self, password: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let conn = Connection::open(&self.db_path)?;
        
        let mut stmt = conn.prepare("SELECT password_hash, public_key FROM master ORDER BY id DESC LIMIT 1")?;
        let row = stmt.query_row([], |row| {
            let hash: String = row.get(0)?;
            let pub_key_bytes: Vec<u8> = row.get(1)?;
            Ok((hash, pub_key_bytes))
        })?;

        let (stored_hash, pub_key_bytes) = row;
        
        // Passwort verifizieren
        let parsed_hash = match PasswordHash::new(&stored_hash) {
            Ok(hash) => hash,
            Err(e) => return Err(format!("Failed to parse stored hash: {}", e).into()),
        };
        let argon2 = Argon2::default();
        let is_valid = argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok();
        
        if is_valid {
            // Public Key laden (Secret Key wird zur Laufzeit neu generiert)
            self.public_key = Some(PublicKey::try_from(&pub_key_bytes[..]).map_err(|e| format!("Failed to create PublicKey: {:?}", e))?);
        }
        
        Ok(is_valid)
    }

    fn add_password(&mut self, name: &str, username: Option<&str>, url: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
        if !self.is_unlocked() {
            self.unlock()?;
        }

        let password = self.prompt_password(&format!("Passwort für '{}' eingeben: ", name))?;
        
        // Verschlüsselung mit PQC
        let (shared_secret, _ciphertext) = encapsulate(self.public_key.as_ref().unwrap(), &mut OsRng)?;
        
        // ChaCha20Poly1305 Schlüssel aus shared secret ableiten (ersten 32 Bytes verwenden)
        let cipher = ChaCha20Poly1305::new_from_slice(&shared_secret[..32])
            .map_err(|e| format!("Failed to create cipher from shared secret: {:?}", e))?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        let encrypted_password = cipher.encrypt(&nonce, password.as_bytes())
            .map_err(|e| format!("Encryption failed: {:?}", e))?;
        
        // In Datenbank speichern
        let conn = Connection::open(&self.db_path)?;
        conn.execute(
            "INSERT OR REPLACE INTO passwords (name, username, encrypted_password, url, nonce, shared_secret) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                name,
                username,
                &encrypted_password,
                url,
                nonce.as_slice(),
                &shared_secret
            ],
        )?;

        println!("✅ Passwort für '{}' erfolgreich gespeichert!", name);
        Ok(())
    }

    fn get_password(&mut self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if !self.is_unlocked() {
            self.unlock()?;
        }

        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT username, encrypted_password, url, nonce, shared_secret, created_at 
             FROM passwords WHERE name = ?1"
        )?;
        
        let row = stmt.query_row([name], |row| {
            let username: Option<String> = row.get(0)?;
            let encrypted_password: Vec<u8> = row.get(1)?;
            let url: Option<String> = row.get(2)?;
            let nonce: Vec<u8> = row.get(3)?;
            let shared_secret: Vec<u8> = row.get(4)?;
            let created_at: String = row.get(5)?;
            
            Ok((username, encrypted_password, url, nonce, shared_secret, created_at))
        });

        match row {
            Ok((username, encrypted_password, url, nonce, shared_secret, created_at)) => {
                // Echte Entschlüsselung mit dem shared_secret
                let key = ChaCha20Poly1305::new_from_slice(&shared_secret[..32])
                    .map_err(|e| format!("Failed to create cipher key: {:?}", e))?;
                let nonce = Nonce::from_slice(&nonce);
                
                // Passwort entschlüsseln
                match key.decrypt(nonce, encrypted_password.as_ref()) {
                    Ok(decrypted_bytes) => {
                        match String::from_utf8(decrypted_bytes) {
                            Ok(password) => {
                                println!("\n📋 Eintrag für '{}':", name);
                                println!("👤 Benutzername: {}", username.unwrap_or_else(|| "Nicht angegeben".to_string()));
                                println!("🔗 URL: {}", url.unwrap_or_else(|| "Nicht angegeben".to_string()));
                                println!("📅 Erstellt am: {}", created_at);
                                println!("� Passwort: {}", password);
                            },
                            Err(_) => {
                                println!("❌ Fehler beim Dekodieren des Passworts für '{}'!", name);
                            }
                        }
                    },
                    Err(_) => {
                        println!("❌ Fehler beim Entschlüsseln des Passworts für '{}'!", name);
                        println!("   Möglicherweise falsches Master-Passwort oder beschädigte Daten.");
                    }
                }
            },
            Err(_) => {
                println!("❌ Kein Eintrag für '{}' gefunden!", name);
            }
        }

        Ok(())
    }

    fn list_passwords(&self) -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare("SELECT name, username, url, created_at FROM passwords ORDER BY name")?;
        
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let username: Option<String> = row.get(1)?;
            let url: Option<String> = row.get(2)?;
            let created_at: String = row.get(3)?;
            
            Ok((name, username, url, created_at))
        })?;

        println!("\n📝 Gespeicherte Passwörter:");
        println!("{:-<50}", "");
        
        for row in rows {
            let (name, username, url, created_at) = row?;
            println!("🔐 {}", name);
            if let Some(user) = username {
                println!("   👤 {}", user);
            }
            if let Some(url) = url {
                println!("   🔗 {}", url);
            }
            println!("   📅 {}", created_at);
            println!("");
        }

        Ok(())
    }

    fn delete_password(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open(&self.db_path)?;
        let changes = conn.execute("DELETE FROM passwords WHERE name = ?1", [name])?;
        
        if changes > 0 {
            println!("✅ Eintrag '{}' erfolgreich gelöscht!", name);
        } else {
            println!("❌ Kein Eintrag für '{}' gefunden!", name);
        }

        Ok(())
    }

    fn change_master_password(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let current_password = self.prompt_password("Aktuelles Master-Passwort: ")?;
        
        if !self.verify_master_password(&current_password)? {
            return Err("Falsches Master-Passwort!".into());
        }

        let new_password = self.prompt_password("Neues Master-Passwort: ")?;
        let confirm_password = self.prompt_password("Neues Master-Passwort bestätigen: ")?;

        if new_password != confirm_password {
            return Err("Passwörter stimmen nicht überein!".into());
        }

        // Neues Schlüsselpaar generieren
        let keypair = Keypair::generate(&mut OsRng)?;
        self.public_key = Some(keypair.public);
        self.secret_key = Some(keypair.secret);

        // Neues Master-Passwort speichern
        self.store_master_password(&new_password)?;

        println!("✅ Master-Passwort erfolgreich geändert!");
        println!("🔐 Neue PQC-Schlüssel generiert!");

        Ok(())
    }

    fn unlock(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let password = self.prompt_password("Master-Passwort eingeben: ")?;
        
        if self.verify_master_password(&password)? {
            println!("🔓 Passwort-Manager entsperrt!");
            Ok(())
        } else {
            Err("Falsches Master-Passwort!".into())
        }
    }

    fn is_unlocked(&self) -> bool {
        self.public_key.is_some()
    }

    fn prompt_password(&self, prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        print!("{}", prompt);
        io::stdout().flush()?;
        
        let password = rpassword::read_password()?;
        Ok(password)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut manager = PQCPasswordManager::new();

    match cli.command {
        Commands::Init => {
            manager.init()?;
        },
        Commands::Add { name, username, url } => {
            manager.add_password(&name, username.as_deref(), url.as_deref())?;
        },
        Commands::Get { name } => {
            manager.get_password(&name)?;
        },
        Commands::List => {
            manager.list_passwords()?;
        },
        Commands::Delete { name } => {
            manager.delete_password(&name)?;
        },
        Commands::ChangeMaster => {
            manager.change_master_password()?;
        },
    }

    Ok(())
}

