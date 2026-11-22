//! CLI skeleton for common DID-wallet operations.
//!
//! Handlers are stubs: wire them to [`crate::wallet::WalletTrait`] next.

use crate::keystore::StoreFile;
use crate::wallet::Wallet;
use crate::wallet::WalletTrait;
use bip39::{Language, Mnemonic, WordCount};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "IdentiyWallet",
    author,
    version,
    about = "Local DID identity wallet",
    long_about = None
)]
pub struct Cli {
    /// Encrypted keystore path (default: /tmp/keystore.ebin)
    #[arg(long, global = true, env = "IDW_STORE")]
    pub store: Option<PathBuf>,

    /// Vault password (prefer env in real use)
    #[arg(long, global = true, env = "IDW_PASSWORD")]
    pub password: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a new wallet (generate mnemonic + encrypt to store)
    Init {
        /// Optional password; generated if omitted
        #[arg(long)]
        password: Option<String>,
    },

    /// Import an existing BIP39 mnemonic into the store
    Import {
        /// Space-separated mnemonic (or pass via stdin later)
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        password: Option<String>,
    },

    /// Export the mnemonic from the store
    Export {
        /// Output file path (default: stdout)
        #[arg(long)]
        password: Option<String>,
    },

    /// Unlock vault and derive identity for this session
    Unlock {
        #[arg(long)]
        password: String,
        /// BIP44 account index (MetaMask path m/44'/60'/0'/0/{index})
        #[arg(long, default_value_t = 0)]
        index: u32,
        /// DID method: `key` (default) or `web` (requires --did)
        #[arg(long, value_enum, default_value_t = DidMethodArg::Key)]
        method: DidMethodArg,
        /// Full DID for `did:web` (e.g. did:web:example.com:user:alice)
        #[arg(long)]
        did: Option<String>,
    },

    /// Clear unlocked session material
    Lock {
        #[arg(long)]
        password: String,
    },

    /// Show high-level wallet / identity status
    Status,

    /// Identity card (local DID document overlay)
    #[command(subcommand)]
    Card(CardCmd),

    /// DID document / auth flows
    #[command(subcommand)]
    Did(DidCmd),

    /// Sign payloads with the unlocked key
    #[command(subcommand)]
    Sign(SignCmd),

    /// Verify signatures / JWS
    #[command(subcommand)]
    Verify(VerifyCmd),
}

/// Supported unlock DID methods.
///
/// First-class: [`DidMethodArg::Key`], [`DidMethodArg::Web`].
#[derive(Clone, Debug, ValueEnum)]
pub enum DidMethodArg {
    /// did:key — derived from the wallet public key
    Key,
    /// did:web — requires `--did did:web:...`
    Web,
    /// did:jwk — derived from the wallet public key
    Jwk,
    /// did:ethr — not wired yet
    Eth,
}

impl DidMethodArg {
    pub fn to_wallet_options(
        &self,
        did: Option<String>,
    ) -> Result<crate::wallet::DIDOptions, String> {
        use crate::wallet::DIDOptions;
        match self {
            Self::Key => Ok(DIDOptions::Key),
            Self::Jwk => Ok(DIDOptions::Jwk),
            Self::Web => {
                let did = did.ok_or_else(|| {
                    String::from(
                        "--did is required when --method web (e.g. --did did:web:example.com)",
                    )
                })?;
                Ok(DIDOptions::Web(Some(did)))
            }
            Self::Eth => Ok(DIDOptions::Eth(did)),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum CardCmd {
    /// Print DID, label, and document
    Show,
    /// Local-only patches (does not rotate the DID)
    Update {
        #[arg(long)]
        label: Option<String>,
        /// Repeatable alsoKnownAs IRIs
        #[arg(long = "also-known-as")]
        also_known_as: Vec<String>,
        /// JSON file of service endpoints (optional; wire later)
        #[arg(long)]
        services_file: Option<PathBuf>,
    },
    /// Print public JWK only
    Jwk,
}

#[derive(Subcommand, Debug)]
pub enum DidCmd {
    /// Resolve / return the current DID document
    Resolve,
    /// Prove control of the DID (challenge → JWS)
    Authenticate {
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        domain: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SignCmd {
    /// Sign a JSON claims object as JWS
    Claims {
        /// Inline JSON string
        #[arg(long, conflicts_with = "file")]
        json: Option<String>,
        /// Path to a JSON file
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum VerifyCmd {
    /// Verify a JWS with a public JWK / current wallet key
    Jws {
        #[arg(long, conflicts_with = "file")]
        jws: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        /// Public JWK JSON (default: unlocked wallet public key)
        #[arg(long)]
        jwk: Option<String>,
    },
}

/// Dispatch entrypoint. Replace stubs with wallet calls.
pub async fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Init { password } => {
            let path = cli.store.as_ref().map(|p| p.to_str()).flatten();
            let pass = password.as_deref();
            let mut wallet = Wallet::new(StoreFile::default(path), pass).unwrap();
            let mnemonic = Mnemonic::generate_in(Language::English, WordCount::Words12).unwrap();
            let result = wallet.init(&mnemonic.to_string(), pass);
            let pass = result.unwrap();
            println!(
                "[stub] init store={:?} password_set={:?}",
                cli.store,
                if password.is_some() {
                    "yes"
                } else {
                    pass.as_str()
                },
            );
        }
        Commands::Import { mnemonic, password } => {
            let path = cli.store.as_ref().map(|p| p.to_str()).flatten();
            let pass = password.as_deref();
            let mut wallet = Wallet::new(StoreFile::default(path), pass).unwrap();
            let _ = wallet.init(&mnemonic.to_string(), pass);
            println!(
                "[stub] import store={:?} password_set={}",
                cli.store,
                password.is_some()
            );
        }
        Commands::Export { password } => {
            let path = cli.store.as_ref().map(|p| p.to_str()).flatten();
            let pass = password.as_deref().unwrap();
            let mut wallet = Wallet::open(StoreFile::default(path), pass).unwrap();
            if wallet.unlock(pass, 0, None).await.is_ok() {
                let mnemonic = wallet.mnemonic().unwrap();
                println!("{mnemonic}");
            } else {
                println!("unlock failed");
            }
        }
        Commands::Unlock {
            password,
            index,
            method,
            did,
        } => {
            let opt = method.to_wallet_options(did)?;
            let path = cli.store.as_ref().map(|p| p.to_str()).flatten();
            let pass = password.as_str();
            let mut wallet = Wallet::open(StoreFile::default(path), pass).unwrap();

            if wallet.unlock(pass, index, Some(opt.clone())).await.is_ok() {
            } else {
                println!("unlock failed");
            }
            println!(
                "[stub] unlock index={index} method={method:?} opt_ready store={:?} ({opt:?})",
                cli.store
            );
        }
        Commands::Lock { password } => {
            let path = cli.store.as_ref().map(|p| p.to_str()).flatten();
            let pass = password.as_str();
            let mut wallet = Wallet::open(StoreFile::default(path), pass).unwrap();
            wallet.lock();
            println!("[stub] lock");
        }
        Commands::Status => {
            println!("[stub] status store={:?}", cli.store);
        }
        Commands::Card(cmd) => match cmd {
            CardCmd::Show => println!("[stub] card show"),
            CardCmd::Update {
                label,
                also_known_as,
                services_file,
            } => {
                println!(
                    "[stub] card update label={label:?} aka={also_known_as:?} services={services_file:?}"
                );
            }
            CardCmd::Jwk => println!("[stub] card jwk"),
        },
        Commands::Did(cmd) => match cmd {
            DidCmd::Resolve => println!("[stub] did resolve"),
            DidCmd::Authenticate { challenge, domain } => {
                println!("[stub] did authenticate challenge={challenge:?} domain={domain:?}");
            }
        },
        Commands::Sign(cmd) => match cmd {
            SignCmd::Claims { json, file } => {
                println!("[stub] sign claims json={json:?} file={file:?}");
            }
        },
        Commands::Verify(cmd) => match cmd {
            VerifyCmd::Jws { jws, file, jwk } => {
                println!("[stub] verify jws jws={jws:?} file={file:?} jwk={jwk:?}");
            }
        },
    }
    Ok(())
}
