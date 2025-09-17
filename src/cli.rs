use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pqc-password-manager")]
#[command(about = "Ein Post-Quantum-Cryptography sicherer Passwort-Manager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialisiert den Passwort-Manager mit einem Master-Passwort
    Init,
    /// Füge ein neues Passwort hinzu
    Add {
        /// Name/Service für das Passwort
        name: String,
        /// Benutzername (optional)
        #[arg(short = 'u', long)]
        username: Option<String>,
        /// URL/Website (optional)
        #[arg(short = 'l', long)]
        url: Option<String>,
    },
    /// Zeige ein gespeichertes Passwort an
    Get {
        /// Name des Services
        name: String,
    },
    /// Liste alle gespeicherten Services auf
    List,
    /// Lösche einen Eintrag
    Delete {
        /// Name des Services
        name: String,
    },
    /// Ändere das Master-Passwort
    ChangeMaster,
    /// Benchmark KDF parameters for optimal security/performance balance
    BenchmarkKdf,
    /// Export encrypted database backup
    Export {
        /// Output file path
        #[arg(short = 'f', long)]
        file: String,
    },
    /// Import from encrypted backup
    Import {
        /// Input file path
        #[arg(short = 'f', long)]
        file: String,
    },
    /// TOTP (Time-based One-Time Password) management
    Totp {
        #[command(subcommand)]
        command: TotpCommands,
    },
}

#[derive(Subcommand)]
pub enum TotpCommands {
    /// Add a TOTP entry
    Add {
        /// Service name
        name: String,
        /// TOTP secret or otpauth:// URI
        #[arg(short = 's', long)]
        secret: Option<String>,
        /// otpauth:// URI (alternative to secret)
        #[arg(short = 'u', long)]
        uri: Option<String>,
        /// Issuer name (optional)
        #[arg(short = 'i', long)]
        issuer: Option<String>,
    },
    /// Get current TOTP code for a service
    Get {
        /// Service name
        name: String,
    },
    /// List all TOTP entries
    List,
    /// Delete a TOTP entry
    Delete {
        /// Service name
        name: String,
    },
}