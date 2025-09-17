use pqc_kyber::{Keypair, PublicKey, SecretKey, encapsulate};
use chacha20poly1305::aead::OsRng;

pub type PqcKeypair = Keypair;
pub type PqcPublicKey = PublicKey;
pub type PqcSecretKey = SecretKey;

/// Generiert ein neues Post-Quantum Kyber512 Schlüsselpaar
pub fn generate_keypair() -> Result<PqcKeypair, Box<dyn std::error::Error>> {
    let keypair = Keypair::generate(&mut OsRng)?;
    Ok(keypair)
}

/// Führt Schlüsselkapselung durch und gibt shared secret zurück
pub fn perform_encapsulation(public_key: &PqcPublicKey) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (shared_secret, _ciphertext) = encapsulate(public_key, &mut OsRng)?;
    Ok(shared_secret.to_vec())
}

/// Konvertiert PublicKey zu Bytes für Speicherung
pub fn public_key_to_bytes(public_key: &PqcPublicKey) -> &[u8] {
    public_key
}

/// Konvertiert Bytes zurück zu PublicKey
pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PqcPublicKey, Box<dyn std::error::Error>> {
    let public_key = PqcPublicKey::try_from(bytes)
        .map_err(|e| format!("Failed to create PublicKey: {:?}", e))?;
    Ok(public_key)
}