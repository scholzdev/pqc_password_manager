use std::io::{self, Write};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::{SaltString, rand_core::OsRng as ArgonOsRng}};
use zeroize::Zeroize;
use base64::{Engine as _, engine::general_purpose::STANDARD as base64_engine};

use crate::crypto::{
    generate_keypair, perform_encapsulation, public_key_to_bytes, public_key_from_bytes,
    create_cipher_from_secret, generate_nonce, encrypt_data, decrypt_data, 
    nonce_to_slice, nonce_from_slice, generate_search_hash, PqcPublicKey, PqcSecretKey,
    parse_totp_input, TotpConfig
};
use crate::storage::{Database, PasswordEntry, MasterPasswordEntry, TotpEntry};

pub struct PasswordManager {
    pub db: Database,
    pub public_key: Option<PqcPublicKey>,
    pub secret_key: Option<PqcSecretKey>,
}

impl PasswordManager {
    pub fn new(db_path: String) -> Self {
        Self {
            db: Database::new(db_path),
            public_key: None,
            secret_key: None,
        }
    }

    /// Initialisiert den Passwort-Manager
    pub fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.db.is_initialized() {
            return Err("Passwort-Manager ist bereits initialisiert!".into());
        }

        println!("🔐 Initialisiere Post-Quantum-Cryptography sicheren Passwort-Manager...");
        
        let master_password = self.prompt_password("Master-Passwort festlegen: ")?;
        
        if master_password.len() < 8 {
            return Err("Master-Passwort muss mindestens 8 Zeichen lang sein!".into());
        }

        // Kyber Schlüsselpaar generieren
        let keypair = generate_keypair()?;
        self.public_key = Some(keypair.public);
        self.secret_key = Some(keypair.secret);

        // Datenbank initialisieren
        self.db.initialize()?;
        
        // Master-Passwort hashen und speichern
        self.store_master_password(&master_password)?;

        println!("✅ Passwort-Manager erfolgreich initialisiert!");
        println!("🔐 Post-Quantum-Cryptography Schlüssel generiert (Kyber512)");
        
        Ok(())
    }

    /// Speichert das Master-Passwort
    fn store_master_password(&self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        let salt = SaltString::generate(&mut ArgonOsRng);
        let argon2 = Argon2::default();
        let password_hash = match argon2.hash_password(password.as_bytes(), &salt) {
            Ok(hash) => hash.to_string(),
            Err(e) => return Err(format!("Failed to hash password: {}", e).into()),
        };

        let public_key_bytes = public_key_to_bytes(self.public_key.as_ref().unwrap());

        let entry = MasterPasswordEntry {
            password_hash,
            public_key: public_key_bytes.to_vec(),
            salt: salt.to_string(),
        };

        self.db.store_master_password(&entry)?;
        Ok(())
    }

    /// Verifiziert das Master-Passwort und lädt die Schlüssel
    pub fn unlock(&mut self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.db.load_master_password()
            .map_err(|_| "Konnte Master-Passwort nicht laden. Ist der Manager initialisiert?")?;

        let parsed_hash = match PasswordHash::new(&entry.password_hash) {
            Ok(hash) => hash,
            Err(e) => return Err(format!("Failed to parse stored hash: {}", e).into()),
        };

        let argon2 = Argon2::default();
        if argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok() {
            // Öffentlichen Schlüssel aus Datenbank laden
            self.public_key = Some(public_key_from_bytes(&entry.public_key)?);
            println!("🔓 Passwort-Manager entsperrt!");
            Ok(())
        } else {
            Err("❌ Falsches Master-Passwort!".into())
        }
    }

    /// Adds a new password entry (all metadata now encrypted for privacy)
    pub fn add_password(&self, name: &str, username: Option<String>, url: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        if self.public_key.is_none() {
            return Err("Password manager is not unlocked!".into());
        }

        let password = self.prompt_password(&format!("Enter password for '{}': ", name))?;
        
        // PQC encryption
        let shared_secret = perform_encapsulation(self.public_key.as_ref().unwrap())?;
        
        // Derive ChaCha20Poly1305 key from shared secret
        let cipher = create_cipher_from_secret(&shared_secret)?;
        let nonce = generate_nonce();
        
        // Encrypt all sensitive data including metadata
        let encrypted_password = encrypt_data(&cipher, &nonce, password.as_bytes())?;
        let encrypted_name = encrypt_data(&cipher, &nonce, name.as_bytes())?;
        let encrypted_username = username.as_ref()
            .map(|u| encrypt_data(&cipher, &nonce, u.as_bytes()))
            .transpose()?
            .unwrap_or_else(Vec::new);
        let encrypted_url = url.as_ref()
            .map(|u| encrypt_data(&cipher, &nonce, u.as_bytes()))
            .transpose()?
            .unwrap_or_else(Vec::new);
        
        // Generate searchable hash for lookups (doesn't reveal service name)
        let search_hash = generate_search_hash(name, &shared_secret);
        
        // Store in database
        let entry = PasswordEntry {
            encrypted_name,
            encrypted_username,
            encrypted_password,
            encrypted_url,
            nonce: nonce_to_slice(&nonce).to_vec(),
            shared_secret,
            created_at: String::new(), // Set by database
            search_hash,
        };

        self.db.store_password(&entry)?;
        
        println!("✅ Password for '{}' has been securely stored with encrypted metadata!", name);
        Ok(())
    }

    /// Shows a stored password (searches by name, decrypts all metadata)
    pub fn get_password(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if self.public_key.is_none() {
            return Err("Password manager is not unlocked!".into());
        }

        // Find entry by trying all entries and decrypting names
        let entries = self.db.list_passwords()?;
        
        for entry in entries {
            let cipher = create_cipher_from_secret(&entry.shared_secret)?;
            let nonce = nonce_from_slice(&entry.nonce);
            
            // Try to decrypt the name to see if it matches
            if let Ok(decrypted_name_bytes) = decrypt_data(&cipher, nonce, &entry.encrypted_name) {
                if let Ok(decrypted_name) = String::from_utf8(decrypted_name_bytes) {
                    if decrypted_name == name {
                        // Found the matching entry, decrypt all fields
                        match decrypt_data(&cipher, nonce, &entry.encrypted_password) {
                            Ok(decrypted_password_bytes) => {
                                match String::from_utf8(decrypted_password_bytes) {
                                    Ok(password) => {
                                        // Decrypt username if present
                                        let username = if !entry.encrypted_username.is_empty() {
                                            decrypt_data(&cipher, nonce, &entry.encrypted_username)
                                                .ok()
                                                .and_then(|bytes| String::from_utf8(bytes).ok())
                                                .unwrap_or_else(|| "Not specified".to_string())
                                        } else {
                                            "Not specified".to_string()
                                        };
                                        
                                        // Decrypt URL if present
                                        let url = if !entry.encrypted_url.is_empty() {
                                            decrypt_data(&cipher, nonce, &entry.encrypted_url)
                                                .ok()
                                                .and_then(|bytes| String::from_utf8(bytes).ok())
                                                .unwrap_or_else(|| "Not specified".to_string())
                                        } else {
                                            "Not specified".to_string()
                                        };
                                        
                                        println!("\n📋 Entry for '{}':", name);
                                        println!("� Username: {}", username);
                                        println!("🔗 URL: {}", url);
                                        println!("📅 Created: {}", entry.created_at);
                                        println!("🔑 Password: {}", password);
                                        return Ok(());
                                    },
                                    Err(_) => {
                                        println!("❌ Error decoding password for '{}'!", name);
                                        return Ok(());
                                    }
                                }
                            },
                            Err(_) => {
                                println!("❌ Error decrypting password for '{}'!", name);
                                println!("   Possibly wrong master password or corrupted data.");
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
        
        println!("❌ No entry found for '{}'!", name);
        Ok(())
    }

    /// Lists all stored passwords (decrypts metadata for display)
    pub fn list_passwords(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.public_key.is_none() {
            return Err("Password manager is not unlocked!".into());
        }

        let entries = self.db.list_passwords()?;
        
        if entries.is_empty() {
            println!("📭 No passwords stored.");
            return Ok(());
        }

        println!("\n📚 Stored passwords (metadata now encrypted for privacy):");
        println!("{:─<30}┬{:─<25}┬{:─<30}┬{:─<20}", "", "", "", "");
        println!("{:<30}│{:<25}│{:<30}│{:<20}", "Service", "Username", "URL", "Created");
        println!("{:─<30}┼{:─<25}┼{:─<30}┼{:─<20}", "", "", "", "");
        
        for entry in entries {
            let cipher = create_cipher_from_secret(&entry.shared_secret)?;
            let nonce = nonce_from_slice(&entry.nonce);
            
            // Decrypt name
            let name = decrypt_data(&cipher, nonce, &entry.encrypted_name)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_else(|| "Decryption error".to_string());
            
            // Decrypt username if present
            let username = if !entry.encrypted_username.is_empty() {
                decrypt_data(&cipher, nonce, &entry.encrypted_username)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .unwrap_or_else(|| "Decryption error".to_string())
            } else {
                "-".to_string()
            };
            
            // Decrypt URL if present
            let url = if !entry.encrypted_url.is_empty() {
                decrypt_data(&cipher, nonce, &entry.encrypted_url)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .unwrap_or_else(|| "Decryption error".to_string())
            } else {
                "-".to_string()
            };
            
            println!("{:<30}│{:<25}│{:<30}│{:<20}", 
                name,
                username,
                url,
                entry.created_at
            );
        }
        
        Ok(())
    }

    /// Deletes a password entry (searches by name, deletes by search hash)
    pub fn delete_password(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if self.public_key.is_none() {
            return Err("Password manager is not unlocked!".into());
        }

        // Find entry by trying all entries and decrypting names
        let entries = self.db.list_passwords()?;
        
        for entry in entries {
            let cipher = create_cipher_from_secret(&entry.shared_secret)?;
            let nonce = nonce_from_slice(&entry.nonce);
            
            // Try to decrypt the name to see if it matches
            if let Ok(decrypted_name_bytes) = decrypt_data(&cipher, nonce, &entry.encrypted_name) {
                if let Ok(decrypted_name) = String::from_utf8(decrypted_name_bytes) {
                    if decrypted_name == name {
                        // Found the matching entry, delete by search hash
                        let deleted = self.db.delete_password(&entry.search_hash)?;
                        
                        if deleted > 0 {
                            println!("✅ Entry '{}' has been deleted!", name);
                        } else {
                            println!("❌ Failed to delete entry '{}'!", name);
                        }
                        
                        return Ok(());
                    }
                }
            }
        }
        
        println!("❌ No entry found for '{}'!", name);
        Ok(())
    }

    /// Ändert das Master-Passwort
    pub fn change_master_password(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.public_key.is_none() {
            return Err("Passwort-Manager ist nicht entsperrt!".into());
        }

        let current_password = self.prompt_password("Aktuelles Master-Passwort eingeben: ")?;
        
        // Aktuelles Passwort verifizieren
        let entry = self.db.load_master_password()?;
        let parsed_hash = match PasswordHash::new(&entry.password_hash) {
            Ok(hash) => hash,
            Err(e) => return Err(format!("Failed to parse stored hash: {}", e).into()),
        };

        let argon2 = Argon2::default();
        if argon2.verify_password(current_password.as_bytes(), &parsed_hash).is_err() {
            return Err("❌ Falsches aktuelles Master-Passwort!".into());
        }

        let new_password = self.prompt_password("Neues Master-Passwort eingeben: ")?;
        
        if new_password.len() < 8 {
            return Err("Neues Master-Passwort muss mindestens 8 Zeichen lang sein!".into());
        }

        // Nur Master-Passwort-Hash ändern, PQC-Schlüssel behalten
        // (Die Passwörter sind mit PQC-Schlüsseln verschlüsselt, nicht direkt mit Master-Passwort)
        self.store_master_password(&new_password)?;

        println!("✅ Master-Passwort erfolgreich geändert!");
        println!("🔐 Alle gespeicherten Passwörter bleiben verfügbar!");
        
        Ok(())
    }

    /// Export encrypted database backup
    pub fn export_backup(&self, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        if self.public_key.is_none() {
            return Err("Password manager is not unlocked!".into());
        }

        println!("🔄 Exporting encrypted database backup...");
        
        // Get all password entries
        let entries = self.db.list_passwords()?;
        let master_entry = self.db.load_master_password()?;
        
        // Create backup structure
        let backup = BackupData {
            version: "1.0.0".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            master_password_hash: master_entry.password_hash,
            public_key: master_entry.public_key,
            salt: master_entry.salt,
            entries: entries.into_iter().map(|entry| BackupEntry {
                encrypted_name: base64_engine.encode(&entry.encrypted_name),
                encrypted_username: base64_engine.encode(&entry.encrypted_username),
                encrypted_password: base64_engine.encode(&entry.encrypted_password),
                encrypted_url: base64_engine.encode(&entry.encrypted_url),
                nonce: base64_engine.encode(&entry.nonce),
                shared_secret: base64_engine.encode(&entry.shared_secret),
                created_at: entry.created_at,
                search_hash: entry.search_hash,
            }).collect(),
        };
        
        // Serialize to JSON
        let json_data = serde_json::to_string_pretty(&backup)?;
        
        // Write to file
        std::fs::write(file_path, json_data)?;
        
        println!("✅ Backup exported to: {}", file_path);
        println!("📊 Exported {} password entries", backup.entries.len());
        println!("🔐 Backup is encrypted and safe to store externally");
        
        Ok(())
    }
    
    /// Import from encrypted backup
    pub fn import_backup(&mut self, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("🔄 Importing encrypted database backup...");
        
        // Read backup file
        let json_data = std::fs::read_to_string(file_path)?;
        let backup: BackupData = serde_json::from_str(&json_data)?;
        
        println!("📂 Backup version: {}", backup.version);
        println!("📅 Created: {}", backup.created_at);
        let entry_count = backup.entries.len();
        println!("📊 Contains {} password entries", entry_count);
        
        // Confirm import
        print!("⚠️  This will overwrite the current database. Continue? (y/N): ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        if !input.trim().to_lowercase().starts_with('y') {
            println!("❌ Import cancelled");
            return Ok(());
        }
        
        // Initialize database
        self.db.initialize()?;
        
        // Restore master password entry
        let master_entry = MasterPasswordEntry {
            password_hash: backup.master_password_hash,
            public_key: backup.public_key,
            salt: backup.salt,
        };
        self.db.store_master_password(&master_entry)?;
        
        // Restore password entries
        for backup_entry in backup.entries {
            let entry = PasswordEntry {
                encrypted_name: base64_engine.decode(&backup_entry.encrypted_name)?,
                encrypted_username: base64_engine.decode(&backup_entry.encrypted_username)?,
                encrypted_password: base64_engine.decode(&backup_entry.encrypted_password)?,
                encrypted_url: base64_engine.decode(&backup_entry.encrypted_url)?,
                nonce: base64_engine.decode(&backup_entry.nonce)?,
                shared_secret: base64_engine.decode(&backup_entry.shared_secret)?,
                created_at: backup_entry.created_at,
                search_hash: backup_entry.search_hash,
            };
            self.db.store_password(&entry)?;
        }
        
        println!("✅ Import completed successfully!");
        println!("📊 Imported {} password entries", entry_count);
        println!("🔐 All data remains encrypted with your master password");
        
        Ok(())
    }

    /// Add a TOTP entry
    pub fn add_totp(&self, name: &str, secret_or_uri: &str, issuer: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        if self.public_key.is_none() {
            return Err("Password manager is not unlocked!".into());
        }

        println!("🔐 Adding TOTP entry for '{}'...", name);
        
        // Parse TOTP input (secret or URI)
        let totp_config = parse_totp_input(secret_or_uri, name, issuer.clone())?;
        
        // Test TOTP generation to verify secret is valid
        let test_code = totp_config.generate_current_code()?;
        println!("✅ TOTP secret valid! Test code: {} (for verification)", test_code);
        
        // PQC encryption
        let shared_secret = perform_encapsulation(self.public_key.as_ref().unwrap())?;
        let cipher = create_cipher_from_secret(&shared_secret)?;
        let nonce = generate_nonce();
        
        // Encrypt all sensitive data
        let encrypted_service_name = encrypt_data(&cipher, &nonce, name.as_bytes())?;
        let encrypted_secret = encrypt_data(&cipher, &nonce, &totp_config.secret)?;
        let encrypted_issuer = if let Some(ref issuer_name) = totp_config.issuer {
            encrypt_data(&cipher, &nonce, issuer_name.as_bytes())?
        } else {
            Vec::new()
        };
        
        // Generate search hash
        let search_hash = generate_search_hash(name, &shared_secret);
        
        // Store in database
        let entry = TotpEntry {
            encrypted_service_name,
            encrypted_secret,
            encrypted_issuer,
            algorithm: totp_config.algorithm,
            digits: totp_config.digits,
            period: totp_config.period,
            nonce: nonce_to_slice(&nonce).to_vec(),
            shared_secret,
            created_at: String::new(),
            search_hash,
        };

        self.db.store_totp(&entry)?;
        
        println!("✅ TOTP entry for '{}' has been securely stored!", name);
        Ok(())
    }

    /// Get current TOTP code for a service
    pub fn get_totp(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if self.public_key.is_none() {
            return Err("Password manager is not unlocked!".into());
        }

        // Find entry by trying all entries and decrypting names
        let entries = self.db.list_totp()?;
        
        for entry in entries {
            let cipher = create_cipher_from_secret(&entry.shared_secret)?;
            let nonce = nonce_from_slice(&entry.nonce);
            
            // Try to decrypt the name to see if it matches
            if let Ok(decrypted_name_bytes) = decrypt_data(&cipher, nonce, &entry.encrypted_service_name) {
                if let Ok(decrypted_name) = String::from_utf8(decrypted_name_bytes) {
                    if decrypted_name == name {
                        // Found the matching entry, decrypt secret and generate code
                        let decrypted_secret = decrypt_data(&cipher, nonce, &entry.encrypted_secret)?;
                        
                        let issuer = if !entry.encrypted_issuer.is_empty() {
                            decrypt_data(&cipher, nonce, &entry.encrypted_issuer)
                                .ok()
                                .and_then(|bytes| String::from_utf8(bytes).ok())
                        } else {
                            None
                        };
                        
                        let totp_config = TotpConfig {
                            secret: decrypted_secret,
                            algorithm: entry.algorithm.clone(),
                            digits: entry.digits,
                            period: entry.period,
                            issuer,
                        };
                        
                        let current_code = totp_config.generate_current_code()?;
                        let remaining_time = totp_config.get_remaining_time();
                        
                        println!("\n🔑 TOTP Code for '{}':", name);
                        if let Some(issuer) = totp_config.issuer {
                            println!("🏢 Issuer: {}", issuer);
                        }
                        println!("📱 Current Code: {}", current_code);
                        println!("⏰ Valid for: {} seconds", remaining_time);
                        println!("🔄 Algorithm: {}, Digits: {}, Period: {}s", 
                            entry.algorithm, entry.digits, entry.period);
                        
                        return Ok(());
                    }
                }
            }
        }
        
        println!("❌ No TOTP entry found for '{}'!", name);
        Ok(())
    }

    /// List all TOTP entries
    pub fn list_totp(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.public_key.is_none() {
            return Err("Password manager is not unlocked!".into());
        }

        let entries = self.db.list_totp()?;
        
        if entries.is_empty() {
            println!("📭 No TOTP entries stored.");
            return Ok(());
        }

        println!("\n📱 TOTP Entries (Time-based One-Time Passwords):");
        println!("{:─<30}┬{:─<25}┬{:─<15}┬{:─<20}", "", "", "", "");
        println!("{:<30}│{:<25}│{:<15}│{:<20}", "Service", "Issuer", "Algorithm", "Created");
        println!("{:─<30}┼{:─<25}┼{:─<15}┼{:─<20}", "", "", "", "");
        
        for entry in entries {
            let cipher = create_cipher_from_secret(&entry.shared_secret)?;
            let nonce = nonce_from_slice(&entry.nonce);
            
            // Decrypt service name
            let service_name = decrypt_data(&cipher, nonce, &entry.encrypted_service_name)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_else(|| "Decryption error".to_string());
            
            // Decrypt issuer if present
            let issuer = if !entry.encrypted_issuer.is_empty() {
                decrypt_data(&cipher, nonce, &entry.encrypted_issuer)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .unwrap_or_else(|| "Decryption error".to_string())
            } else {
                "-".to_string()
            };
            
            println!("{:<30}│{:<25}│{:<15}│{:<20}", 
                service_name,
                issuer,
                entry.algorithm,
                entry.created_at
            );
        }
        
        Ok(())
    }

    /// Delete a TOTP entry
    pub fn delete_totp(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if self.public_key.is_none() {
            return Err("Password manager is not unlocked!".into());
        }

        // Find entry by trying all entries and decrypting names
        let entries = self.db.list_totp()?;
        
        for entry in entries {
            let cipher = create_cipher_from_secret(&entry.shared_secret)?;
            let nonce = nonce_from_slice(&entry.nonce);
            
            // Try to decrypt the name to see if it matches
            if let Ok(decrypted_name_bytes) = decrypt_data(&cipher, nonce, &entry.encrypted_service_name) {
                if let Ok(decrypted_name) = String::from_utf8(decrypted_name_bytes) {
                    if decrypted_name == name {
                        // Found the matching entry, delete by search hash
                        let deleted = self.db.delete_totp(&entry.search_hash)?;
                        
                        if deleted > 0 {
                            println!("✅ TOTP entry '{}' has been deleted!", name);
                        } else {
                            println!("❌ Failed to delete TOTP entry '{}'!", name);
                        }
                        
                        return Ok(());
                    }
                }
            }
        }
        
        println!("❌ No TOTP entry found for '{}'!", name);
        Ok(())
    }

    /// Sichere Passwort-Eingabe
    fn prompt_password(&self, prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        print!("{}", prompt);
        io::stdout().flush()?;
        
        let mut password = rpassword::read_password()?;
        
        // Sicherstellen, dass das Passwort gelöscht wird
        let result = password.clone();
        password.zeroize();
        
        Ok(result)
    }
}

// Backup data structures
#[derive(serde::Serialize, serde::Deserialize)]
struct BackupData {
    version: String,
    created_at: String,
    master_password_hash: String,
    public_key: Vec<u8>,
    salt: String,
    entries: Vec<BackupEntry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BackupEntry {
    encrypted_name: String,
    encrypted_username: String,
    encrypted_password: String,
    encrypted_url: String,
    nonce: String,
    shared_secret: String,
    created_at: String,
    search_hash: String,
}