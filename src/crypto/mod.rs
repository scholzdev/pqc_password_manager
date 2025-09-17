pub mod pqc;
pub mod symmetric;
pub mod kdf;
pub mod security;
pub mod totp;

pub use pqc::*;
pub use symmetric::*;
pub use kdf::*;
pub use security::*;
pub use totp::*;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Generates a deterministic search hash for encrypted metadata lookups
/// This allows searching without revealing the actual service name
pub fn generate_search_hash(service_name: &str, master_key: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    service_name.hash(&mut hasher);
    master_key.hash(&mut hasher);
    format!("search_{:016x}", hasher.finish())
}