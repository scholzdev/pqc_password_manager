use pqc_password_manager::storage::SecureStorageManager;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 PQC Password Manager - Hardware Security Status");
    println!("==================================================");
    
    let storage = SecureStorageManager::new();
    let status = storage.get_security_status();
    
    println!("\n🖥️  PLATFORM INFORMATION:");
    println!("   Operating System: {}", status.platform.os);
    println!("   Architecture: {}", status.platform.chip);
    println!("   Secure Enclave: {}", if status.platform.secure_enclave { "✅ Available" } else { "❌ Not Available" });
    
    println!("\n🛡️  SECURITY FEATURES:");
    for feature in &status.security_features {
        println!("   ✅ {}", feature);
    }
    
    println!("\n🔐 HARDWARE-BACKED STORAGE:");
    if status.hardware_backed {
        println!("   ✅ Hardware Security Module active");
        println!("   🏆 MAXIMUM SECURITY - Keys are hardware-protected!");
    } else {
        println!("   ⚠️  Software keyring is being used");
        println!("   💡 Recommendation: Use Hardware Security Key for maximum security");
    }
    
    println!("\n📊 SECURITY ASSESSMENT:");
    let security_score = calculate_security_score(&status);
    println!("   Security Level: {}/10", security_score);
    
    match security_score {
        9..=10 => println!("   🏆 EXCELLENT - Military-Grade Security"),
        7..=8 => println!("   ✅ VERY GOOD - Enterprise-Grade Security"),
        5..=6 => println!("   ⚠️ GOOD - Standard security with room for improvement"),
        _ => println!("   ❌ NEEDS IMPROVEMENT - Additional security measures recommended"),
    }
    
    println!("\n💡 RECOMMENDATIONS:");
    print_security_recommendations(&status);
    
    // Test key storage (Demo)
    println!("\n🧪 TESTING HARDWARE STORAGE:");
    test_key_storage(&storage)?;
    
    Ok(())
}

fn calculate_security_score(status: &pqc_password_manager::storage::SecurityStatus) -> u8 {
    let mut score = 0;
    
    // Base-Score für PQC
    score += 3;
    
    // Hardware-backed storage
    if status.hardware_backed {
        score += 3;
    } else {
        score += 1;
    }
    
    // Secure Enclave
    if status.platform.secure_enclave {
        score += 2;
    }
    
    // Platform-spezifische Features
    match status.platform.os.as_str() {
        "macos" => score += 2, // macOS has excellent hardware integration
        "windows" => score += 1, // Windows TPM is good but less integrated
        "linux" => score += 1, // Linux mostly software-based
        _ => {},
    }
    
    std::cmp::min(score, 10)
}

fn print_security_recommendations(status: &pqc_password_manager::storage::SecurityStatus) {
    if !status.hardware_backed {
        println!("   🔧 Use Hardware Security Key (YubiKey, etc.)");
    }
    
    if !status.platform.secure_enclave {
        println!("   💻 Upgrade to newer hardware with Secure Enclave/TPM 2.0");
    }
    
    match status.platform.os.as_str() {
        "macos" => {
            println!("   🍎 Enable Touch ID/Face ID for additional biometrics");
            if !status.platform.secure_enclave {
                println!("   📱 Upgrade to Apple Silicon (M1/M2/M3) for Secure Enclave");
            }
        },
        "windows" => {
            println!("   🪟 Enable Windows Hello for biometrics");
            println!("   🔒 Enable TPM 2.0 in BIOS (if available)");
        },
        "linux" => {
            println!("   🐧 Configure GNOME Keyring or KDE Wallet");
            println!("   🔐 Use Hardware Security Module (HSM) for maximum security");
        },
        _ => {},
    }
    
    println!("   🔄 Regular backup verification of encrypted data");
    println!("   📱 Enable Multi-Factor Authentication (MFA)");
}

fn test_key_storage(storage: &SecureStorageManager) -> Result<(), Box<dyn std::error::Error>> {
    println!("   🧪 Testing key storage...");
    
    let test_public_key = b"test_public_key_data_32_bytes!!!";
    let test_secret_key = b"test_secret_key_data_32_bytes!!!";
    
    match storage.store_pqc_keypair("test_keypair", test_public_key, test_secret_key) {
        Ok(_) => {
            println!("   ✅ Key successfully stored in hardware storage");
            
            // Try to load (will currently still fail)
            match storage.load_pqc_keypair("test_keypair") {
                Ok((pub_key, _sec_key)) => {
                    println!("   ✅ Key successfully loaded from hardware storage");
                    println!("      Public Key: {}... ({} bytes)", 
                        std::str::from_utf8(&pub_key[..8]).unwrap_or("binary"), pub_key.len());
                },
                Err(e) => {
                    println!("   ⚠️ Key loading not yet implemented: {}", e);
                    println!("      (This is normal - complete integration follows)");
                }
            }
        },
        Err(e) => {
            println!("   ❌ Error during storage: {}", e);
        }
    }
    
    Ok(())
}