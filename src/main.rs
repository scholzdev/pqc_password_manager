use clap::Parser;
use std::io::{self, Write};
use pqc_password_manager::{Cli, Commands, TotpCommands, PasswordManager};

fn get_db_path() -> String {
    let home_dir = dirs::home_dir().expect("Konnte Home-Verzeichnis nicht finden");
    let db_path = home_dir.join(".pqc_password_manager.db");
    db_path.to_string_lossy().to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let db_path = get_db_path();
    let mut manager = PasswordManager::new(db_path);

    match cli.command {
        Commands::Init => {
            manager.initialize()?;
        },
        Commands::Add { name, username, url } => {
            if !manager.db.is_initialized() {
                eprintln!("❌ Passwort-Manager ist nicht initialisiert! Führen Sie zuerst 'init' aus.");
                std::process::exit(1);
            }

            let master_password = rpassword::prompt_password("Master-Passwort eingeben: ")?;
            manager.unlock(&master_password)?;
            manager.add_password(&name, username, url)?;
        },
        Commands::Get { name } => {
            if !manager.db.is_initialized() {
                eprintln!("❌ Passwort-Manager ist nicht initialisiert! Führen Sie zuerst 'init' aus.");
                std::process::exit(1);
            }

            let master_password = rpassword::prompt_password("Master-Passwort eingeben: ")?;
            manager.unlock(&master_password)?;
            manager.get_password(&name)?;
        },
        Commands::List => {
            if !manager.db.is_initialized() {
                eprintln!("❌ Passwort-Manager ist nicht initialisiert! Führen Sie zuerst 'init' aus.");
                std::process::exit(1);
            }

            let master_password = rpassword::prompt_password("Master-Passwort eingeben: ")?;
            manager.unlock(&master_password)?;
            manager.list_passwords()?;
        },
        Commands::Delete { name } => {
            if !manager.db.is_initialized() {
                eprintln!("❌ Passwort-Manager ist nicht initialisiert! Führen Sie zuerst 'init' aus.");
                std::process::exit(1);
            }

            let master_password = rpassword::prompt_password("Master-Passwort eingeben: ")?;
            manager.unlock(&master_password)?;
            manager.delete_password(&name)?;
        },
        Commands::ChangeMaster => {
            if !manager.db.is_initialized() {
                eprintln!("❌ Passwort-Manager ist nicht initialisiert! Führen Sie zuerst 'init' aus.");
                std::process::exit(1);
            }

            let master_password = rpassword::prompt_password("Master-Passwort eingeben: ")?;
            manager.unlock(&master_password)?;
            manager.change_master_password()?;
        },
        Commands::BenchmarkKdf => {
            println!("🚀 Starting KDF benchmark (this may take a few minutes)...\n");
            pqc_password_manager::crypto::benchmark_kdf_comprehensive()?;
        },
        Commands::Export { file } => {
            if !manager.db.is_initialized() {
                eprintln!("❌ Password manager is not initialized! Run 'init' first.");
                std::process::exit(1);
            }

            let master_password = rpassword::prompt_password("Enter master password: ")?;
            manager.unlock(&master_password)?;
            manager.export_backup(&file)?;
        },
        Commands::Import { file } => {
            // Import will initialize the database, so we don't check if it's already initialized
            manager.import_backup(&file)?;
            println!("💡 You can now use the imported database with your master password.");
        },
        Commands::Totp { command } => {
            if !manager.db.is_initialized() {
                eprintln!("❌ Password manager is not initialized! Run 'init' first.");
                std::process::exit(1);
            }

            let master_password = rpassword::prompt_password("Enter master password: ")?;
            manager.unlock(&master_password)?;

            match command {
                TotpCommands::Add { name, secret, uri, issuer } => {
                    // Determine input source
                    let input = if let Some(uri_val) = uri {
                        uri_val
                    } else if let Some(secret_val) = secret {
                        secret_val
                    } else {
                        // Interactive input
                        print!("Enter TOTP secret or otpauth:// URI: ");
                        io::stdout().flush()?;
                        let mut input = String::new();
                        io::stdin().read_line(&mut input)?;
                        input.trim().to_string()
                    };
                    
                    manager.add_totp(&name, &input, issuer)?;
                },
                TotpCommands::Get { name } => {
                    manager.get_totp(&name)?;
                },
                TotpCommands::List => {
                    manager.list_totp()?;
                },
                TotpCommands::Delete { name } => {
                    manager.delete_totp(&name)?;
                },
            }
        },
    }

    Ok(())
}