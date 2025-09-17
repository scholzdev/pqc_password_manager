use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce
};

pub type SymmetricCipher = ChaCha20Poly1305;
pub type SymmetricNonce = Nonce;

/// Erstellt einen ChaCha20Poly1305 Cipher aus einem shared secret
pub fn create_cipher_from_secret(shared_secret: &[u8]) -> Result<SymmetricCipher, Box<dyn std::error::Error>> {
    let cipher = ChaCha20Poly1305::new_from_slice(&shared_secret[..32])
        .map_err(|e| format!("Failed to create cipher from shared secret: {:?}", e))?;
    Ok(cipher)
}

/// Generiert eine neue Nonce für die Verschlüsselung
pub fn generate_nonce() -> SymmetricNonce {
    ChaCha20Poly1305::generate_nonce(&mut OsRng)
}

/// Verschlüsselt Daten mit dem gegebenen Cipher und Nonce
pub fn encrypt_data(
    cipher: &SymmetricCipher, 
    nonce: &SymmetricNonce, 
    data: &[u8]
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let encrypted = cipher.encrypt(nonce, data)
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    Ok(encrypted)
}

/// Entschlüsselt Daten mit dem gegebenen Cipher und Nonce
pub fn decrypt_data(
    cipher: &SymmetricCipher, 
    nonce: &SymmetricNonce, 
    encrypted_data: &[u8]
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let decrypted = cipher.decrypt(nonce, encrypted_data)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;
    Ok(decrypted)
}

/// Konvertiert Nonce zu Slice für Speicherung
pub fn nonce_to_slice(nonce: &SymmetricNonce) -> &[u8] {
    nonce.as_slice()
}

/// Konvertiert Slice zurück zu Nonce
pub fn nonce_from_slice(slice: &[u8]) -> &SymmetricNonce {
    Nonce::from_slice(slice)
}