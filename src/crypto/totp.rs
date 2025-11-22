use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use base32::Alphabet;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone)]
pub struct TotpConfig {
    pub secret: Vec<u8>,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
    pub issuer: Option<String>,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            secret: Vec::new(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
            issuer: None,
        }
    }
}

impl TotpConfig {
    /// Generate current TOTP code
    pub fn generate_current_code(&self) -> Result<String, Box<dyn std::error::Error>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        self.generate_code_at_time(now)
    }

    /// Generate TOTP code at specific time
    pub fn generate_code_at_time(&self, timestamp: u64) -> Result<String, Box<dyn std::error::Error>> {
        let counter = timestamp / self.period as u64;
        
        // Create HMAC-SHA1
        let mut mac = HmacSha1::new_from_slice(&self.secret)?;
        mac.update(&counter.to_be_bytes());
        let hmac_result = mac.finalize().into_bytes();
        
        // Dynamic truncation
        let offset = (hmac_result[19] & 0x0f) as usize;
        let code = ((hmac_result[offset] & 0x7f) as u32) << 24
            | (hmac_result[offset + 1] as u32) << 16
            | (hmac_result[offset + 2] as u32) << 8
            | hmac_result[offset + 3] as u32;
        
        let totp_code = code % 10_u32.pow(self.digits);
        Ok(format!("{:0width$}", totp_code, width = self.digits as usize))
    }

    /// Get remaining time until next code
    pub fn get_remaining_time(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.period as u64 - (now % self.period as u64)
    }
}

/// Parse various TOTP input formats
pub fn parse_totp_input(input: &str, _service_name: &str, issuer: Option<String>) -> Result<TotpConfig, Box<dyn std::error::Error>> {
    if input.starts_with("otpauth://totp/") {
        parse_otpauth_uri(input)
    } else {
        // Treat as raw secret
        let normalized_secret = normalize_secret(input)?;
        Ok(TotpConfig {
            secret: normalized_secret,
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
            issuer,
        })
    }
}

/// Parse otpauth:// URI
fn parse_otpauth_uri(uri: &str) -> Result<TotpConfig, Box<dyn std::error::Error>> {
    let url = url::Url::parse(uri)?;
    
    // Extract secret
    let secret_str = url.query_pairs()
        .find(|(key, _)| key == "secret")
        .ok_or("Missing secret in otpauth URI")?
        .1;
    let secret = normalize_secret(&secret_str)?;
    
    // Extract optional parameters
    let algorithm = url.query_pairs()
        .find(|(key, _)| key == "algorithm")
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| "SHA1".to_string());
    
    let digits = url.query_pairs()
        .find(|(key, _)| key == "digits")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(6);
    
    let period = url.query_pairs()
        .find(|(key, _)| key == "period")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(30);
    
    let issuer = url.query_pairs()
        .find(|(key, _)| key == "issuer")
        .map(|(_, v)| v.to_string());
    
    Ok(TotpConfig {
        secret,
        algorithm,
        digits,
        period,
        issuer,
    })
}

/// Normalize TOTP secret (remove spaces, decode base32)
fn normalize_secret(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cleaned = input.replace(" ", "").to_uppercase();
    let decoded = base32::decode(Alphabet::RFC4648 { padding: false }, &cleaned)
        .ok_or("Invalid base32 secret")?;
    Ok(decoded)
}

/// Generate a random TOTP secret for testing
pub fn generate_random_secret() -> Vec<u8> {
    use rand::RngCore;
    let mut secret = vec![0u8; 20]; // 160-bit secret
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

/// Encode secret as base32 for display
pub fn encode_secret_base32(secret: &[u8]) -> String {
    base32::encode(Alphabet::RFC4648 { padding: false }, secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation() {
        // Test vector from RFC 6238
        let secret = b"12345678901234567890";
        let config = TotpConfig {
            secret: secret.to_vec(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
            issuer: None,
        };
        
        // Test known timestamp
        let code = config.generate_code_at_time(1111111109).unwrap();
        assert_eq!(code, "081804");
    }

    #[test]
    fn test_secret_normalization() {
        let secret1 = normalize_secret("JBSW Y3DP EHPK 3PXP").unwrap();
        let secret2 = normalize_secret("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_otpauth_parsing() {
        let uri = "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";
        let config = parse_otpauth_uri(uri).unwrap();
        assert_eq!(config.algorithm, "SHA1");
        assert_eq!(config.digits, 6);
        assert_eq!(config.period, 30);
        assert_eq!(config.issuer, Some("GitHub".to_string()));
    }
}