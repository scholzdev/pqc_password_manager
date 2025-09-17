use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pqc-password-manager")]
#[command(about = "A Post-Quantum-Cryptography secure password manager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize the password manager with a master password
    Init,
    /// Add a new password
    Add {
        /// Name/Service for the password
        name: String,
        /// Username (optional)
        #[arg(short = 'u', long)]
        username: Option<String>,
        /// URL/Website (optional)
        #[arg(short = 'l', long)]
        url: Option<String>,
    },
    /// Show a stored password
    Get {
        /// Service name
        name: String,
    },
    /// List all stored services
    List,
    /// Delete an entry
    Delete {
        /// Service name
        name: String,
    },
    /// Change the master password
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