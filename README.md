# 🔐 PQC Password Manager

A **Post-Quantum Cryptography (PQC) secure** password manager written in Rust, featuring hardware-backed storage and military-grade security.

## 🚀 Features

- **🌐 Post-Quantum Security**: Uses Kyber512 for quantum-resistant key encapsulation  
- **🔒 Modern Encryption**: ChaCha20-Poly1305 for symmetric encryption
- **🕵️ Full Metadata Privacy**: Service names, usernames, and URLs are encrypted
- **📱 TOTP Support**: RFC 6238 compliant Time-based One-Time Passwords with encrypted storage
- **🛡️ Hardware Security**: Integrates with OS-native secure storage:
  - **macOS**: Keychain + Secure Enclave (M1/M2/M3)
  - **Windows**: Credential Manager + TPM 2.0  
  - **Linux**: GNOME Keyring + Hardware Security Modules
- **🔐 Hardened KDF**: Argon2id with pepper and optimized parameters
- **📊 Security Monitoring**: Brute-force detection and incident response
- **🏃 Searchable Encryption**: Find entries without revealing service names
- **💾 Secure Backup**: Export/import with full encryption preservation

## 🔧 Configuration

### Custom KDF Parametersty**: Uses Kyber512 for quantum-resistant key encapsulation
- **🔒 Modern Encryption**: ChaCha20-Poly1305 for symmetric encryption
- **�️ Full Metadata Privacy**: Service names, usernames, and URLs are encrypted
- **�🛡️ Hardware Security**: Integrates with OS-native secure storage:
  - **macOS**: Keychain + Secure Enclave (M1/M2/M3)
  - **Windows**: Credential Manager + TPM 2.0
  - **Linux**: GNOME Keyring + Hardware Security Modules
- **🔐 Hardened KDF**: Argon2id with pepper and optimized parameters
- **📊 Security Monitoring**: Brute-force detection and incident response
- **🏃 Searchable Encryption**: Find entries without revealing service names
- **🔄 Key Rotation**: Automatic password rotation recommendations

## 🏛️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Interface │────│ Password Manager │────│ Hardware Storage│
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
            ┌───────▼────┐ ┌────▼────┐ ┌───▼──────┐
            │ PQC Crypto │ │Database │ │Security  │
            │(Kyber512)  │ │(SQLite) │ │Monitor   │
            └────────────┘ └─────────┘ └──────────┘
```

## 📦 Installation

### Prerequisites
- Rust 1.89.0+ with `edition = "2024"`
- Platform-specific security frameworks:
  - **macOS**: Xcode Command Line Tools
  - **Windows**: Windows SDK
  - **Linux**: libsecret-dev

### Build
```bash
cd pqc_password_manager
cargo build --release
```

## 🎯 Usage

### 1. Initialize (First Time Setup)
```bash
# Initialize with master password and generate PQC keys
./target/release/pqc_password_manager init
```
**Storage locations:**
- **Keys**: Hardware-backed (Keychain/TPM/Keyring)
- **Database**: `~/.pqc_password_manager.db`
- **Config**: Auto-detected optimal security parameters

### 2. Add Passwords
```bash
# Add a new password entry
./target/release/pqc_password_manager add "Gmail" \
  --username "john.doe@gmail.com" \
  --url "https://gmail.com"
```

### 3. Retrieve Passwords
```bash
# Get a stored password (requires master password)
./target/release/pqc_password_manager get "Gmail"
```

### 4. List All Entries
```bash
# Show all stored services
./target/release/pqc_password_manager list
```

### 5. Change Master Password
```bash
# Change master password (preserves all stored passwords)
./target/release/pqc_password_manager change-master
```

### 6. TOTP Management (Time-based One-Time Passwords)
```bash
# Add TOTP entry with Base32 secret
./target/release/pqc_password_manager totp add "Google Auth" \
  --secret "JBSWY3DPEHPK3PXP"

# Add TOTP entry with otpauth:// URI
./target/release/pqc_password_manager totp add "GitHub" \
  --uri "otpauth://totp/GitHub:user@example.com?secret=ABCD&issuer=GitHub"

# Get current TOTP code
./target/release/pqc_password_manager totp get "Google Auth"

# List all TOTP entries
./target/release/pqc_password_manager totp list

# Delete TOTP entry
./target/release/pqc_password_manager totp delete "Google Auth"
```

### 7. Security Status Check
```bash
# Check hardware security capabilities
./target/release/security_check
```

## 🔬 Security Features

### Post-Quantum Cryptography
- **Kyber512**: NIST-standardized lattice-based key encapsulation
- **Future-proof**: Resistant to quantum computer attacks
- **Performance**: Optimized for desktop applications

### Hardware Security Integration
| Platform | Hardware Backing | Biometric Support |
|----------|------------------|-------------------|
| **macOS** | Secure Enclave (M1/M2/M3) | Touch ID / Face ID |
| **Windows** | TPM 2.0 | Windows Hello |
| **Linux** | HSM (if available) | - |

### Key Derivation
- **Algorithm**: Argon2id (hybrid mode)
- **Parameters**: Auto-benchmarked for 500-1000ms delay
- **Salt + Pepper**: Protection against rainbow table attacks
- **Memory**: 64MB+ (OWASP recommendation)

## 🛡️ Security Architecture

### 🕵️ Privacy Protection

**Full Metadata Encryption**: Unlike traditional password managers that store service names, usernames, and URLs in plaintext, our implementation encrypts **all sensitive metadata**.

**What's Protected:**
- ✅ Service names (Gmail, Facebook, etc.) → Encrypted
- ✅ Usernames/emails → Encrypted  
- ✅ URLs/domains → Encrypted
- ✅ Passwords → Encrypted (obviously)
- ✅ Creation timestamps → Plaintext (for sorting only)

**Database Compromise Scenario:**
```
Traditional Password Manager Database Leak:
❌ Reveals: "user has accounts on: Gmail, Facebook, Banking, Netflix..."
❌ Shows: usernames, email addresses, service URLs
❌ Privacy completely compromised

PQC Password Manager Database Leak:
✅ Reveals: only encrypted blobs + creation timestamps
✅ No service names, usernames, or URLs visible
✅ Digital footprint remains private
```

**Searchable Encryption**: Uses deterministic hashes for efficient lookups without revealing service names.

### Threat Model
✅ **Protected Against:**
- Quantum computer attacks (post-2030)
- Database theft (encrypted at rest + metadata privacy)
- Digital footprint analysis (service names encrypted)
- Memory dumps (zeroization)
- Brute force attacks (rate limiting + hardened KDF)
- Rainbow table attacks (salt + pepper)
- Metadata leakage (usernames, URLs, service names encrypted)

⚠️ **Limitations:**
- Requires secure master password
- Vulnerable to keyloggers (use hardware keys)
- Local malware with admin privileges

### Cryptographic Primitives
```
Master Password ─► Argon2id(password, salt, pepper) ─► Authentication Hash
                   ▼
                   Database Access Control
                   ▼
Hardware RNG ─► Kyber512.KeyGen() ─► (Public Key, Secret Key)
                   ▼
                   Kyber512.Encaps() ─► Shared Secret ─► ChaCha20-Poly1305 Key
                   ▼
Metadata (name, username, url) ─► ChaCha20-Poly1305.Encrypt() ─► Encrypted Metadata
Password ─► ChaCha20-Poly1305.Encrypt() ─► Encrypted Password
Service Name + Shared Secret ─► Hash() ─► Search Hash (for lookups)
```

## 📊 Performance

| Operation | Time | Hardware Requirement |
|-----------|------|---------------------|
| Init | ~1s | Hardware RNG |
| Add Password | ~500ms | Hardware encryption |
| Get Password | ~500ms | Hardware decryption |
| KDF (Argon2id) | ~500ms | 64MB RAM |

## �️ Database Inspection

### Privacy-Safe Database Analysis
```bash
# Inspect database without revealing sensitive data
./inspect_db.sh

# Or specify custom database path
./inspect_db.sh /path/to/your/database.db

# Shows encrypted field sizes and statistics only
# No plaintext metadata is displayed
```

**Example Output:**
```
📊 Password Entries (All Metadata Now Encrypted for Privacy):
==============================================================
ID | Search Hash (Preview) | Created    | Name Size | Password Size
1  | search_a1b2c3d4e5f6... | 2025-09-17 | 32 bytes  | 48 bytes
2  | search_f7e8d9c0b1a2... | 2025-09-16 | 28 bytes  | 52 bytes

🛡️ Privacy Protection Status:
✅ Service names: ENCRYPTED
✅ Usernames: ENCRYPTED  
✅ URLs: ENCRYPTED
✅ Passwords: ENCRYPTED
```

## �🔧 Configuration

### Custom KDF Parameters
```bash
# Environment variables for custom security levels
export PQC_PM_MEMORY_COST=131072    # 128MB (high security)
export PQC_PM_TIME_COST=4           # 4 iterations
export PQC_PM_PARALLELISM=8         # 8 threads
```

### Hardware Security Options
```bash
# Force hardware-backed storage
export PQC_PM_REQUIRE_HARDWARE=true

# Backup to software keyring if hardware unavailable
export PQC_PM_FALLBACK_SOFTWARE=false
```

## 🧪 Testing

### Unit Tests
```bash
cargo test
```

### Security Audit
```bash
# Check hardware security status
./target/release/security_check

# Benchmark KDF parameters
./target/release/pqc_password_manager benchmark-kdf
```

### Integration Test
```bash
# Complete workflow test
./test_workflow.sh
```

## 🔄 Migration & Backup

### Export (Emergency)
```bash
# Export encrypted database (requires master password)
./target/release/pqc_password_manager export --file backup.json
```

### Import
```bash
# Import from backup
./target/release/pqc_password_manager import --file backup.json
```



## 🚨 Security Incident Response

### If Compromised
1. **Immediate**: Change master password (`change-master` command)
2. **Important**: All stored passwords remain secure (encrypted with PQC keys)
3. **Urgent**: Only if PQC keys compromised - rotate all stored passwords
4. **Follow-up**: Check for unauthorized access patterns

### Emergency Contact
```bash
# Generate incident report
./target/release/pqc_password_manager incident-report
```

## 📈 Roadmap

- [x] **Full Metadata Encryption** (Complete privacy protection)
- [x] **Searchable Encryption** (Efficient lookups without data leaks)
- [x] **Export/Import Backup** (Secure database backup/restore)
- [x] **KDF Benchmarking** (Optimal security parameter testing)
- [x] **Multi-Factor Authentication** (TOTP integration with encrypted storage)
- [ ] **Key Rotation** (Master password and PQC key rotation)
- [ ] **Hardware Key Support** (YubiKey, etc.)
- [ ] **Secure Sharing** (PQC-based sharing protocol)
- [ ] **Cloud Sync** (E2E encrypted with metadata privacy)
- [ ] **Mobile Apps** (iOS/Android)
- [ ] **Browser Extension**
- [ ] **Zero-Knowledge Architecture**
- [ ] **Fuzzy Search** (Encrypted similarity matching)

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Security Review Process
- All cryptographic changes require security review
- Hardware integration must be tested on target platforms
- Performance benchmarks required for KDF changes

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This is cryptographic software. While we follow best practices and use well-established algorithms, 
use at your own risk. For high-security environments, consider professional security audit.

## 🙏 Acknowledgments

- **NIST**: For PQC standardization
- **Rust Crypto**: For excellent cryptographic libraries
- **Security Community**: For continuous improvement feedback

---

**Built with ❤️ and 🦀 Rust for a post-quantum future**