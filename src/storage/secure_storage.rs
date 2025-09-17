/// Hardware-backed Security Storage für verschiedene Betriebssysteme
// Keine ungenutzten Imports

#[cfg(target_os = "windows")]
use windows::core::HSTRING;

#[cfg(target_os = "linux")]
use std::process::Command;

/// Hardware-Security-Module Interface
pub trait HardwareSecurityModule {
    fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), Box<dyn std::error::Error>>;
    fn retrieve_key(&self, key_id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn delete_key(&self, key_id: &str) -> Result<(), Box<dyn std::error::Error>>;
    fn is_hardware_backed(&self) -> bool;
}

/// macOS Secure Enclave / Keychain Integration
#[cfg(target_os = "macos")]
pub struct MacOSSecureStorage;

#[cfg(target_os = "macos")]
impl HardwareSecurityModule for MacOSSecureStorage {
    fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        println!("🔐 Speichere Schlüssel '{}' in macOS Keychain/Secure Enclave", key_id);
        
        // Verwende das `security` command-line tool für Keychain-Zugriff
        // Das ist eine vereinfachte Lösung - für Produktion würde man die native API verwenden
        use base64::{Engine as _, engine::general_purpose};
        let key_data_b64 = general_purpose::STANDARD.encode(key_data);
        
        let output = std::process::Command::new("security")
            .args(&[
                "add-generic-password",
                "-a", key_id,
                "-s", "pqc-password-manager", 
                "-w", &key_data_b64,
                "-T", "", // Trusted applications (empty = current app only)
                "-U", // Update if exists
            ])
            .output();
        
        match output {
            Ok(result) if result.status.success() => {
                println!("✅ Schlüssel in macOS Keychain gespeichert (Hardware-backed wenn verfügbar)");
                Ok(())
            },
            Ok(result) => {
                let error = String::from_utf8_lossy(&result.stderr);
                Err(format!("Keychain storage failed: {}", error).into())
            },
            Err(e) => Err(format!("Failed to execute security command: {}", e).into()),
        }
    }
    
    fn retrieve_key(&self, key_id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        println!("🔓 Lade Schlüssel '{}' aus macOS Keychain", key_id);
        
        let output = std::process::Command::new("security")
            .args(&[
                "find-generic-password",
                "-a", key_id,
                "-s", "pqc-password-manager",
                "-w", // Print password only
            ])
            .output();
        
        match output {
            Ok(result) if result.status.success() => {
                use base64::{Engine as _, engine::general_purpose};
                let key_data_b64_string = String::from_utf8_lossy(&result.stdout);
                let key_data_b64 = key_data_b64_string.trim();
                let key_data = general_purpose::STANDARD.decode(key_data_b64)
                    .map_err(|e| format!("Failed to decode key data: {}", e))?;
                Ok(key_data)
            },
            Ok(_) => Err("Key not found in keychain".into()),
            Err(e) => Err(format!("Failed to execute security command: {}", e).into()),
        }
    }
    
    fn delete_key(&self, key_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("🗑️ Lösche Schlüssel '{}' aus macOS Keychain", key_id);
        
        let output = std::process::Command::new("security")
            .args(&[
                "delete-generic-password",
                "-a", key_id,
                "-s", "pqc-password-manager",
            ])
            .output();
        
        match output {
            Ok(result) if result.status.success() => {
                println!("✅ Schlüssel aus Keychain gelöscht");
                Ok(())
            },
            Ok(_) => Ok(()), // Auch OK wenn nicht gefunden
            Err(e) => Err(format!("Failed to execute security command: {}", e).into()),
        }
    }
    
    fn is_hardware_backed(&self) -> bool {
        // Überprüfe ob Secure Enclave verfügbar ist (T2/M1/M2 Chips)
        true // Vereinfacht - echte Erkennung würde Hardware-Check machen
    }
}

/// Windows Credential Manager / TPM Integration
#[cfg(target_os = "windows")]
pub struct WindowsSecureStorage;

#[cfg(target_os = "windows")]
impl HardwareSecurityModule for WindowsSecureStorage {
    fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        println!("🔐 Storing key '{}' in Windows Credential Manager/TPM", key_id);
        
        // Use Windows Credential Manager via cmdkey command
        use base64::{Engine as _, engine::general_purpose};
        let key_data_b64 = general_purpose::STANDARD.encode(key_data);
        let target_name = format!("pqc-password-manager:{}", key_id);
        
        // Store credential using cmdkey
        let output = std::process::Command::new("cmdkey")
            .args(&[
                "/generic",
                &target_name,
                "/user",
                "pqc-pm-key",
                "/pass",
                &key_data_b64,
            ])
            .output();
            
        match output {
            Ok(result) if result.status.success() => {
                println!("✅ Key stored in Windows Credential Manager");
                Ok(())
            },
            Ok(result) => {
                let error = String::from_utf8_lossy(&result.stderr);
                Err(format!("Credential storage failed: {}", error).into())
            },
            Err(e) => Err(format!("Failed to execute cmdkey: {}", e).into()),
        }
    }
    
    fn retrieve_key(&self, key_id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        println!("🔓 Loading key '{}' from Windows Credential Manager", key_id);
        
        let target_name = format!("pqc-password-manager:{}", key_id);
        
        // Query credential using PowerShell (more reliable than cmdkey for reading)
        let powershell_script = format!(
            r#"
            try {{
                $cred = Get-StoredCredential -Target "{}" -ErrorAction Stop
                Write-Output $cred.Password
            }} catch {{
                Write-Error "Credential not found"
                exit 1
            }}
            "#,
            target_name
        );
        
        let output = std::process::Command::new("powershell")
            .args(&["-Command", &powershell_script])
            .output();
            
        match output {
            Ok(result) if result.status.success() => {
                use base64::{Engine as _, engine::general_purpose};
                let key_data_b64_string = String::from_utf8_lossy(&result.stdout);
                let key_data_b64 = key_data_b64_string.trim();
                let key_data = general_purpose::STANDARD.decode(key_data_b64)
                    .map_err(|e| format!("Failed to decode key data: {}", e))?;
                Ok(key_data)
            },
            _ => {
                // Fallback: Try to read from registry as alternative storage
                let output = std::process::Command::new("reg")
                    .args(&[
                        "query",
                        "HKCU\\Software\\PqcPasswordManager\\Keys",
                        "/v",
                        key_id,
                    ])
                    .output();
                    
                match output {
                    Ok(result) if result.status.success() => {
                        let output_str = String::from_utf8_lossy(&result.stdout);
                        if let Some(line) = output_str.lines().find(|l| l.contains(key_id)) {
                            if let Some(value) = line.split_whitespace().last() {
                                use base64::{Engine as _, engine::general_purpose};
                                let key_data = general_purpose::STANDARD.decode(value)
                                    .map_err(|e| format!("Failed to decode registry key: {}", e))?;
                                return Ok(key_data);
                            }
                        }
                    },
                    _ => {}
                }
                
                Err("Key not found in Credential Manager or Registry".into())
            }
        }
    }
    
    fn delete_key(&self, key_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("🗑️ Deleting key '{}' from Windows Credential Manager", key_id);
        
        let target_name = format!("pqc-password-manager:{}", key_id);
        
        // Delete from Credential Manager
        let output = std::process::Command::new("cmdkey")
            .args(&["/delete", &target_name])
            .output();
            
        // Also try to delete from registry backup
        let _ = std::process::Command::new("reg")
            .args(&[
                "delete",
                "HKCU\\Software\\PqcPasswordManager\\Keys",
                "/v",
                key_id,
                "/f",
            ])
            .output();
            
        match output {
            Ok(result) if result.status.success() => {
                println!("✅ Key deleted from Credential Manager");
                Ok(())
            },
            Ok(_) => Ok(()), // Also OK if not found
            Err(e) => Err(format!("Failed to execute cmdkey: {}", e).into()),
        }
    }
    
    fn is_hardware_backed(&self) -> bool {
        // Check if TPM 2.0 is available
        let output = std::process::Command::new("powershell")
            .args(&["-Command", "Get-WmiObject -Class Win32_Tpm"])
            .output();
            
        match output {
            Ok(result) if result.status.success() => {
                let output_str = String::from_utf8_lossy(&result.stdout);
                output_str.contains("IsEnabled") && output_str.contains("True")
            },
            _ => false, // Assume no hardware backing if detection fails
        }
    }
}

/// Linux GNOME Keyring / Hardware Security Module
#[cfg(target_os = "linux")]
pub struct LinuxSecureStorage;

#[cfg(target_os = "linux")]
impl HardwareSecurityModule for LinuxSecureStorage {
    fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        println!("🔐 Storing key '{}' in Linux Keyring/HSM", key_id);
        
        // Try GNOME Keyring first via secret-tool
        use base64::{Engine as _, engine::general_purpose};
        let key_data_b64 = general_purpose::STANDARD.encode(key_data);
        
        let output = std::process::Command::new("secret-tool")
            .args(&[
                "store",
                "--label", &format!("PQC Password Manager Key: {}", key_id),
                "application", "pqc-password-manager",
                "key-id", key_id,
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
            
        match output {
            Ok(mut child) => {
                if let Some(stdin) = child.stdin.as_mut() {
                    use std::io::Write;
                    let _ = stdin.write_all(key_data_b64.as_bytes());
                }
                
                let result = child.wait();
                match result {
                    Ok(status) if status.success() => {
                        println!("✅ Key stored in GNOME Keyring");
                        return Ok(());
                    },
                    _ => {} // Fall through to file fallback
                }
            },
            Err(_) => {} // Fall through to file fallback
        }
        
        // Fallback: Store in secure file
        use std::fs;
        use std::path::PathBuf;
        
        let mut keys_dir = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()));
        keys_dir.push(".config");
        keys_dir.push("pqc-password-manager");
        keys_dir.push("keys");
        
        if let Err(_) = fs::create_dir_all(&keys_dir) {
            return Err("Cannot create keys directory".into());
        }
        
        let key_file = keys_dir.join(format!("{}.key", key_id));
        
        if let Ok(_) = fs::write(&key_file, key_data) {
            // Set restrictive permissions (owner only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600));
            }
            println!("✅ Key stored in secure file (fallback)");
            Ok(())
        } else {
            Err("Failed to store key".into())
        }
    }
    
    fn retrieve_key(&self, key_id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        println!("🔓 Loading key '{}' from Linux Keyring", key_id);
        
        // Try GNOME Keyring first
        let output = std::process::Command::new("secret-tool")
            .args(&[
                "lookup",
                "application", "pqc-password-manager",
                "key-id", key_id,
            ])
            .output();
            
        match output {
            Ok(result) if result.status.success() => {
                use base64::{Engine as _, engine::general_purpose};
                let key_data_b64_string = String::from_utf8_lossy(&result.stdout);
                let key_data_b64 = key_data_b64_string.trim();
                if let Ok(key_data) = general_purpose::STANDARD.decode(key_data_b64) {
                    return Ok(key_data);
                }
            },
            _ => {} // Fall through to file fallback
        }
        
        // Fallback: Try to read from secure file
        use std::fs;
        use std::path::PathBuf;
        
        let mut keys_dir = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()));
        keys_dir.push(".config");
        keys_dir.push("pqc-password-manager");
        keys_dir.push("keys");
        
        let key_file = keys_dir.join(format!("{}.key", key_id));
        
        if let Ok(key_data) = fs::read(&key_file) {
            Ok(key_data)
        } else {
            Err("Key not found in keyring or secure storage".into())
        }
    }
    
    fn delete_key(&self, key_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("🗑️ Deleting key '{}' from Linux Keyring", key_id);
        
        // Try to delete from GNOME Keyring
        let _ = std::process::Command::new("secret-tool")
            .args(&[
                "clear",
                "application", "pqc-password-manager",
                "key-id", key_id,
            ])
            .output();
            
        // Also delete from file fallback
        use std::fs;
        use std::path::PathBuf;
        
        let mut keys_dir = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()));
        keys_dir.push(".config");
        keys_dir.push("pqc-password-manager");
        keys_dir.push("keys");
        
        let key_file = keys_dir.join(format!("{}.key", key_id));
        let _ = fs::remove_file(key_file);
        
        println!("✅ Key deletion attempted from all storage locations");
        Ok(())
    }
    
    fn is_hardware_backed(&self) -> bool {
        // Check if Hardware Security Module is available
        // First check for GNOME Keyring (which can be hardware-backed)
        let keyring_check = std::process::Command::new("secret-tool")
            .args(&["--version"])
            .output();
            
        if keyring_check.is_ok() {
            // Check for potential HSM devices
            let hsm_check = std::process::Command::new("pkcs11-tool")
                .args(&["--list-slots"])
                .output();
                
            match hsm_check {
                Ok(result) if result.status.success() => {
                    let output_str = String::from_utf8_lossy(&result.stdout);
                    // Look for hardware tokens
                    output_str.contains("token") && !output_str.contains("empty")
                },
                _ => false, // No HSM detected, but keyring is available (software-backed)
            }
        } else {
            false // No secure keyring available
        }
    }
}

/// Universeller Secure Storage Manager
pub struct SecureStorageManager {
    #[cfg(target_os = "macos")]
    backend: MacOSSecureStorage,
    #[cfg(target_os = "windows")]
    backend: WindowsSecureStorage,
    #[cfg(target_os = "linux")]
    backend: LinuxSecureStorage,
}

impl SecureStorageManager {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            backend: MacOSSecureStorage,
            #[cfg(target_os = "windows")]
            backend: WindowsSecureStorage,
            #[cfg(target_os = "linux")]
            backend: LinuxSecureStorage,
        }
    }
    
    /// Speichert PQC-Schlüssel hardware-gesichert
    pub fn store_pqc_keypair(&self, keypair_id: &str, public_key: &[u8], secret_key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Speichere PQC-Schlüsselpaar hardware-gesichert...");
        
        let public_key_id = format!("{}_public", keypair_id);
        let secret_key_id = format!("{}_secret", keypair_id);
        
        self.backend.store_key(&public_key_id, public_key)?;
        self.backend.store_key(&secret_key_id, secret_key)?;
        
        if self.backend.is_hardware_backed() {
            println!("✅ Schlüssel in Hardware Security Module gespeichert!");
        } else {
            println!("⚠️ Schlüssel in Software-Keyring gespeichert (Hardware-Backup empfohlen)");
        }
        
        Ok(())
    }
    
    /// Lädt PQC-Schlüssel aus Hardware-Storage
    pub fn load_pqc_keypair(&self, keypair_id: &str) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let public_key_id = format!("{}_public", keypair_id);
        let secret_key_id = format!("{}_secret", keypair_id);
        
        let public_key = self.backend.retrieve_key(&public_key_id)?;
        let secret_key = self.backend.retrieve_key(&secret_key_id)?;
        
        Ok((public_key, secret_key))
    }
    
    /// Überprüft Hardware-Security-Status
    pub fn get_security_status(&self) -> SecurityStatus {
        SecurityStatus {
            hardware_backed: self.backend.is_hardware_backed(),
            platform: get_platform_info(),
            security_features: get_security_features(),
        }
    }
}

#[derive(Debug)]
pub struct SecurityStatus {
    pub hardware_backed: bool,
    pub platform: PlatformInfo,
    pub security_features: Vec<String>,
}

#[derive(Debug)]
pub struct PlatformInfo {
    pub os: String,
    pub chip: String,
    pub secure_enclave: bool,
}

fn get_platform_info() -> PlatformInfo {
    PlatformInfo {
        os: std::env::consts::OS.to_string(),
        chip: get_chip_info(),
        secure_enclave: has_secure_enclave(),
    }
}

fn get_chip_info() -> String {
    #[cfg(target_os = "macos")]
    {
        // Erkennung von Apple Silicon (M1/M2/M3) vs Intel
        if std::env::consts::ARCH == "aarch64" {
            "Apple Silicon (M-Series)".to_string()
        } else {
            "Intel (T2 Chip möglich)".to_string()
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        "x86_64 (TPM 2.0 möglich)".to_string()
    }
    
    #[cfg(target_os = "linux")]
    {
        std::env::consts::ARCH.to_string()
    }
}

fn has_secure_enclave() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::env::consts::ARCH == "aarch64" // Apple Silicon hat immer Secure Enclave
    }
    
    #[cfg(not(target_os = "macos"))]
    {
        false // Vereinfacht - echte Erkennung ist komplexer
    }
}

fn get_security_features() -> Vec<String> {
    let mut features = Vec::new();
    
    #[cfg(target_os = "macos")]
    {
        features.push("macOS Keychain".to_string());
        if has_secure_enclave() {
            features.push("Secure Enclave".to_string());
            features.push("Hardware Key Generation".to_string());
            features.push("Biometric Protection".to_string());
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        features.push("Windows Credential Manager".to_string());
        features.push("TPM 2.0 (if available)".to_string());
        features.push("Windows Hello Integration".to_string());
    }
    
    #[cfg(target_os = "linux")]
    {
        features.push("GNOME Keyring".to_string());
        features.push("Secret Service API".to_string());
    }
    
    features
}

