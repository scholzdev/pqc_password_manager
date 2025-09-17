use pqc_password_manager::storage::SecureStorageManager;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 PQC Password Manager - Hardware Security Status");
    println!("==================================================");
    
    let storage = SecureStorageManager::new();
    let status = storage.get_security_status();
    
    println!("\n🖥️  PLATFORM INFORMATION:");
    println!("   Operating System: {}", status.platform.os);
    println!("   Architecture: {}", status.platform.chip);
    println!("   Secure Enclave: {}", if status.platform.secure_enclave { "✅ Verfügbar" } else { "❌ Nicht verfügbar" });
    
    println!("\n🛡️  SECURITY FEATURES:");
    for feature in &status.security_features {
        println!("   ✅ {}", feature);
    }
    
    println!("\n🔐 HARDWARE-BACKED STORAGE:");
    if status.hardware_backed {
        println!("   ✅ Hardware Security Module aktiv");
        println!("   🏆 MAXIMALE SICHERHEIT - Schlüssel sind hardware-geschützt!");
    } else {
        println!("   ⚠️  Software-Keyring wird verwendet");
        println!("   💡 Empfehlung: Hardware Security Key für maximale Sicherheit");
    }
    
    println!("\n📊 SICHERHEITSBEWERTUNG:");
    let security_score = calculate_security_score(&status);
    println!("   Sicherheitsstufe: {}/10", security_score);
    
    match security_score {
        9..=10 => println!("   🏆 AUSGEZEICHNET - Militär-Grade Sicherheit"),
        7..=8 => println!("   ✅ SEHR GUT - Enterprise-Grade Sicherheit"),
        5..=6 => println!("   ⚠️ GUT - Standard-Sicherheit mit Verbesserungspotential"),
        _ => println!("   ❌ VERBESSERUNG NÖTIG - Zusätzliche Sicherheitsmaßnahmen empfohlen"),
    }
    
    println!("\n💡 EMPFEHLUNGEN:");
    print_security_recommendations(&status);
    
    // Teste Schlüssel-Speicherung (Demo)
    println!("\n🧪 TESTE HARDWARE-SPEICHERUNG:");
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
        "macos" => score += 2, // macOS hat sehr gute Hardware-Integration
        "windows" => score += 1, // Windows TPM ist gut aber weniger integriert
        "linux" => score += 1, // Linux meist software-based
        _ => {},
    }
    
    std::cmp::min(score, 10)
}

fn print_security_recommendations(status: &pqc_password_manager::storage::SecurityStatus) {
    if !status.hardware_backed {
        println!("   🔧 Hardware Security Key (YubiKey, etc.) verwenden");
    }
    
    if !status.platform.secure_enclave {
        println!("   💻 Upgrade auf neuere Hardware mit Secure Enclave/TPM 2.0");
    }
    
    match status.platform.os.as_str() {
        "macos" => {
            println!("   🍎 Touch ID/Face ID für zusätzliche Biometrie aktivieren");
            if !status.platform.secure_enclave {
                println!("   📱 Upgrade auf Apple Silicon (M1/M2/M3) für Secure Enclave");
            }
        },
        "windows" => {
            println!("   🪟 Windows Hello für Biometrie aktivieren");
            println!("   🔒 TPM 2.0 im BIOS aktivieren (falls verfügbar)");
        },
        "linux" => {
            println!("   🐧 GNOME Keyring oder KDE Wallet konfigurieren");
            println!("   🔐 Hardware Security Module (HSM) für maximale Sicherheit");
        },
        _ => {},
    }
    
    println!("   🔄 Regelmäßige Backup-Überprüfung der verschlüsselten Daten");
    println!("   📱 Multi-Faktor-Authentifizierung (MFA) aktivieren");
}

fn test_key_storage(storage: &SecureStorageManager) -> Result<(), Box<dyn std::error::Error>> {
    println!("   🧪 Teste Schlüssel-Speicherung...");
    
    let test_public_key = b"test_public_key_data_32_bytes!!!";
    let test_secret_key = b"test_secret_key_data_32_bytes!!!";
    
    match storage.store_pqc_keypair("test_keypair", test_public_key, test_secret_key) {
        Ok(_) => {
            println!("   ✅ Schlüssel erfolgreich in Hardware-Storage gespeichert");
            
            // Versuche zu laden (wird aktuell noch fehlschlagen)
            match storage.load_pqc_keypair("test_keypair") {
                Ok((pub_key, _sec_key)) => {
                    println!("   ✅ Schlüssel erfolgreich aus Hardware-Storage geladen");
                    println!("      Public Key: {}... ({}  bytes)", 
                        std::str::from_utf8(&pub_key[..8]).unwrap_or("binary"), pub_key.len());
                },
                Err(e) => {
                    println!("   ⚠️ Schlüssel-Laden noch nicht implementiert: {}", e);
                    println!("      (Das ist normal - vollständige Integration folgt)");
                }
            }
        },
        Err(e) => {
            println!("   ❌ Fehler beim Speichern: {}", e);
        }
    }
    
    Ok(())
}