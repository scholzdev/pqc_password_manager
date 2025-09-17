use argon2::{Argon2, Algorithm, Params, Version};
use rand::{RngCore, rngs::OsRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Security-hardened KDF parameters
pub struct SecureKdfConfig {
    /// Memory cost in KB (recommended: >= 64MB for desktop)
    pub memory_cost: u32,
    /// Time cost (iterations, recommended: >= 3)
    pub time_cost: u32,
    /// Parallelism (recommended: number of CPU cores)
    pub parallelism: u32,
    /// Hash length in bytes
    pub hash_length: u32,
}

impl Default for SecureKdfConfig {
    fn default() -> Self {
        Self {
            memory_cost: 65536,  // 64 MB (OWASP recommendation for desktop)
            time_cost: 3,        // 3 iterations (minimum for security)
            parallelism: 4,      // 4 threads (typical for modern CPUs)
            hash_length: 32,     // 256-bit hash
        }
    }
}

/// Gehärteter Pepper-Store (sollte extern gespeichert werden)
#[derive(ZeroizeOnDrop)]
pub struct Pepper {
    value: [u8; 32],
}

impl Pepper {
    /// Generate new pepper (once per installation)
    pub fn generate() -> Self {
        let mut pepper = [0u8; 32];
        OsRng.fill_bytes(&mut pepper);
        Self { value: pepper }
    }
    
    /// Load pepper from secure source (e.g. Keychain/Registry)
    pub fn load_or_generate() -> Result<Self, Box<dyn std::error::Error>> {
        const PEPPER_KEY_ID: &str = "pqc_password_manager_pepper";
        
        #[cfg(target_os = "macos")]
        {
            // Try to load from macOS Keychain
            use base64::{Engine as _, engine::general_purpose};
            let output = std::process::Command::new("security")
                .args(&[
                    "find-generic-password",
                    "-a", PEPPER_KEY_ID,
                    "-s", "pqc-password-manager-pepper",
                    "-w",
                ])
                .output();
                
            match output {
                Ok(result) if result.status.success() => {
                    let pepper_b64_string = String::from_utf8_lossy(&result.stdout);
                    let pepper_b64 = pepper_b64_string.trim();
                    if let Ok(pepper_bytes) = general_purpose::STANDARD.decode(pepper_b64) {
                        if pepper_bytes.len() == 32 {
                            let mut pepper_array = [0u8; 32];
                            pepper_array.copy_from_slice(&pepper_bytes);
                            return Ok(Self { value: pepper_array });
                        }
                    }
                },
                _ => {} // Fall through to generate new
            }
            
            // Generate new pepper and store it
            let new_pepper = Self::generate();
            let pepper_b64 = general_purpose::STANDARD.encode(&new_pepper.value);
            
            let _ = std::process::Command::new("security")
                .args(&[
                    "add-generic-password",
                    "-a", PEPPER_KEY_ID,
                    "-s", "pqc-password-manager-pepper",
                    "-w", &pepper_b64,
                    "-T", "",
                ])
                .output();
                
            Ok(new_pepper)
        }
        
        #[cfg(target_os = "windows")]
        {
            // Try to load from Windows Registry
            use std::process::Command;
            
            let output = Command::new("reg")
                .args(&[
                    "query",
                    "HKCU\\Software\\PqcPasswordManager",
                    "/v",
                    "Pepper",
                ])
                .output();
                
            match output {
                Ok(result) if result.status.success() => {
                    let output_str = String::from_utf8_lossy(&result.stdout);
                    if let Some(line) = output_str.lines().find(|l| l.contains("Pepper")) {
                        if let Some(value) = line.split_whitespace().last() {
                            use base64::{Engine as _, engine::general_purpose};
                            if let Ok(pepper_bytes) = general_purpose::STANDARD.decode(value) {
                                if pepper_bytes.len() == 32 {
                                    let mut pepper_array = [0u8; 32];
                                    pepper_array.copy_from_slice(&pepper_bytes);
                                    return Ok(Self { value: pepper_array });
                                }
                            }
                        }
                    }
                },
                _ => {} // Fall through to generate new
            }
            
            // Generate new pepper and store it
            let new_pepper = Self::generate();
            use base64::{Engine as _, engine::general_purpose};
            let pepper_b64 = general_purpose::STANDARD.encode(&new_pepper.value);
            
            // Create registry key if it doesn't exist
            let _ = Command::new("reg")
                .args(&["add", "HKCU\\Software\\PqcPasswordManager", "/f"])
                .output();
                
            // Store pepper in registry
            let _ = Command::new("reg")
                .args(&[
                    "add",
                    "HKCU\\Software\\PqcPasswordManager",
                    "/v",
                    "Pepper",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &pepper_b64,
                    "/f",
                ])
                .output();
                
            Ok(new_pepper)
        }
        
        #[cfg(target_os = "linux")]
        {
            // Try to load from file in secure directory
            use std::fs;
            use std::path::PathBuf;
            
            let mut pepper_path = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()));
            pepper_path.push(".config");
            pepper_path.push("pqc-password-manager");
            
            // Create directory if it doesn't exist
            if let Err(_) = fs::create_dir_all(&pepper_path) {
                return Ok(Self::generate()); // Fallback to temporary pepper
            }
            
            pepper_path.push(".pepper");
            
            // Try to read existing pepper
            if let Ok(pepper_data) = fs::read(&pepper_path) {
                if pepper_data.len() == 32 {
                    let mut pepper_array = [0u8; 32];
                    pepper_array.copy_from_slice(&pepper_data);
                    
                    // Set restrictive permissions (owner only)
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&pepper_path, fs::Permissions::from_mode(0o600));
                    }
                    
                    return Ok(Self { value: pepper_array });
                }
            }
            
            // Generate new pepper and store it
            let new_pepper = Self::generate();
            if let Ok(_) = fs::write(&pepper_path, &new_pepper.value) {
                // Set restrictive permissions (owner only)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&pepper_path, fs::Permissions::from_mode(0o600));
                }
            }
            
            Ok(new_pepper)
        }
        
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            // Fallback for other platforms
            Ok(Self::generate())
        }
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}

/// Hardened password-to-key derivation
pub fn derive_key_secure(
    password: &str,
    salt: &[u8],
    pepper: &Pepper,
    config: &SecureKdfConfig,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Pre-hash with pepper (prevents rainbow table attacks)
    let mut combined_input = password.as_bytes().to_vec();
    combined_input.extend_from_slice(pepper.as_bytes());
    
    // Create Argon2id instance with hardened parameters
    let params = Params::new(
        config.memory_cost,
        config.time_cost,
        config.parallelism,
        Some(config.hash_length as usize),
    ).map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    // Compute hash
    let mut hash = vec![0u8; config.hash_length as usize];
    argon2.hash_password_into(&combined_input, salt, &mut hash)
        .map_err(|e| format!("KDF failed: {}", e))?;
    
    // Secure erasure of combined input
    let mut combined_input = combined_input;
    combined_input.zeroize();
    
    Ok(hash)
}

/// Benchmark optimal KDF parameters for this system
pub fn benchmark_kdf_parameters() -> SecureKdfConfig {
    use std::time::Instant;
    
    println!("🔧 Benchmarking KDF parameters for optimal security...");
    
    let test_password = "test_password";
    let test_salt = b"test_salt_16byte";
    let pepper = Pepper::generate();
    
    // Test different parameter combinations
    let configs = vec![
        SecureKdfConfig { memory_cost: 32768, time_cost: 2, parallelism: 2, hash_length: 32 },  // ~100ms
        SecureKdfConfig { memory_cost: 65536, time_cost: 3, parallelism: 4, hash_length: 32 },  // ~500ms
        SecureKdfConfig { memory_cost: 131072, time_cost: 4, parallelism: 4, hash_length: 32 }, // ~1s
    ];
    
    let mut best_config = SecureKdfConfig::default();
    let mut best_time = std::time::Duration::from_secs(u64::MAX);
    
    for config in configs {
        let start = Instant::now();
        if derive_key_secure(test_password, test_salt, &pepper, &config).is_ok() {
            let duration = start.elapsed();
            println!("  Memory: {}KB, Time: {}, Parallelism: {} → {}ms", 
                config.memory_cost, config.time_cost, config.parallelism, duration.as_millis());
            
            // Choose parameters that take ~500ms-1s (OWASP recommendation)
            if duration.as_millis() >= 500 && duration.as_millis() <= 1000 && duration < best_time {
                best_config = config;
                best_time = duration;
            }
        }
    }
    
    println!("✅ Optimal parameters selected: {}ms", best_time.as_millis());
    best_config
}

/// Comprehensive KDF benchmark for security assessment
pub fn benchmark_kdf_comprehensive() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;
    
    println!("🔐 PQC Password Manager - KDF Security Benchmark");
    println!("================================================");
    println!("Testing Argon2id parameters for optimal security/performance balance\n");
    
    let test_password = "benchmark_test_password_2025";
    let test_salt = b"benchmark_salt16";
    let pepper = Pepper::generate();
    
    // Test various parameter combinations
    let test_configs = vec![
        // Low security (fast, for testing)
        ("Low Security (Testing)", SecureKdfConfig { 
            memory_cost: 16384, time_cost: 1, parallelism: 1, hash_length: 32 
        }),
        // Medium security
        ("Medium Security", SecureKdfConfig { 
            memory_cost: 32768, time_cost: 2, parallelism: 2, hash_length: 32 
        }),
        // OWASP Recommended (Desktop)
        ("OWASP Desktop", SecureKdfConfig { 
            memory_cost: 65536, time_cost: 3, parallelism: 4, hash_length: 32 
        }),
        // High security
        ("High Security", SecureKdfConfig { 
            memory_cost: 131072, time_cost: 4, parallelism: 4, hash_length: 32 
        }),
        // Maximum security (slow)
        ("Maximum Security", SecureKdfConfig { 
            memory_cost: 262144, time_cost: 5, parallelism: 8, hash_length: 32 
        }),
    ];
    
    println!("{:<20} | {:>8} | {:>4} | {:>4} | {:>8} | {:>8} | {:<10}", 
        "Configuration", "Memory", "Time", "Par.", "Duration", "Mem MB", "Security");
    println!("{:-<20}-+-{:-<8}-+-{:-<4}-+-{:-<4}-+-{:-<8}-+-{:-<8}-+-{:-<10}", 
        "", "", "", "", "", "", "");
    
    let mut results = Vec::new();
    
    for (name, config) in test_configs {
        let start = Instant::now();
        
        match derive_key_secure(test_password, test_salt, &pepper, &config) {
            Ok(_key) => {
                let duration = start.elapsed();
                let memory_mb = (config.memory_cost as f64) / 1024.0;
                let security_level = if duration.as_millis() < 100 { "⚠️  LOW" }
                    else if duration.as_millis() < 500 { "🟡 MEDIUM" }
                    else if duration.as_millis() < 1000 { "🟢 GOOD" }
                    else if duration.as_millis() < 2000 { "🔵 HIGH" }
                    else { "🟣 MAXIMUM" };
                
                println!("{:<20} | {:>6}KB | {:>4} | {:>4} | {:>6}ms | {:>6.1}MB | {:<10}", 
                    name, config.memory_cost, config.time_cost, config.parallelism, 
                    duration.as_millis(), memory_mb, security_level);
                
                results.push((name, config, duration));
            },
            Err(e) => {
                println!("{:<20} | {:>6}KB | {:>4} | {:>4} | {:>8} | {:>8} | {:<10}", 
                    name, config.memory_cost, config.time_cost, config.parallelism, 
                    "ERROR", "N/A", "FAILED");
                eprintln!("Error with {}: {}", name, e);
            }
        }
    }
    
    println!("\n📊 Benchmark Results Summary:");
    println!("=============================");
    
    // Find recommended configuration (500ms-1s range)
    let recommended = results.iter()
        .filter(|(_, _, duration)| duration.as_millis() >= 500 && duration.as_millis() <= 1000)
        .min_by_key(|(_, _, duration)| duration.as_millis());
    
    if let Some((name, config, duration)) = recommended {
        println!("✅ Recommended Configuration: {}", name);
        println!("   Memory: {}KB ({:.1}MB)", config.memory_cost, config.memory_cost as f64 / 1024.0);
        println!("   Time Cost: {}", config.time_cost);
        println!("   Parallelism: {}", config.parallelism);
        println!("   Duration: {}ms", duration.as_millis());
    } else {
        println!("⚠️  No configuration found in optimal 500-1000ms range");
        if let Some((name, _, duration)) = results.iter().min_by_key(|(_, _, d)| d.as_millis()) {
            println!("💡 Fastest configuration: {} ({}ms)", name, duration.as_millis());
        }
    }
    
    println!("\n🔍 Security Guidelines:");
    println!("=======================");
    println!("• Target: 500-1000ms (OWASP recommendation for desktop)");
    println!("• Minimum: 100ms (mobile/embedded)");
    println!("• High Security: 1-2 seconds");
    println!("• Memory: At least 32MB, preferably 64MB+");
    println!("• Parallelism: Match CPU core count");
    
    println!("\n⚡ Performance vs Security Trade-offs:");
    println!("======================================");
    println!("• Faster login = Lower security against brute force");
    println!("• Higher memory cost = Harder to parallelize attacks");
    println!("• More iterations = Exponentially harder to crack");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_kdf_security() {
        let config = SecureKdfConfig::default();
        let pepper = Pepper::generate();
        let salt = b"test_salt_16byte";
        
        let key1 = derive_key_secure("password123", salt, &pepper, &config).unwrap();
        let key2 = derive_key_secure("password124", salt, &pepper, &config).unwrap();
        
        // Different passwords must generate different keys
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
    }
}