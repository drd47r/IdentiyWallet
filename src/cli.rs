//! CLI skeleton for common DID-wallet operations.
//!
//! Handlers are stubs: wire them to [`crate::wallet::WalletTrait`] next.

use crate::keystore::StoreFile;
use crate::wallet::DidRequest::{self, Authenticate};
use crate::wallet::{DIDOptions, DidResponse, Wallet, WalletError, WalletTrait};
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
#[derive(Clone)]
pub struct Cli {
    /// Encrypted keystore path (default: /tmp/keystore.ebin)
    #[arg(long, global = true, env = "IDW_STORE")]
    pub store: Option<PathBuf>,

    /// Unlock index (default: 0)
    #[arg(long, global = true, env = "IDW_INDEX")]
    pub index: Option<u32>,

    /// Vault password (prefer env in real use)
    #[arg(long, global = true, env = "IDW_PASSWORD")]
    pub password: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub async fn unlock(
        &mut self,
        didopt: Option<DidMethodArg>,
        did: Option<String>,
    ) -> Result<Wallet<StoreFile>, WalletError> {
        let path = self.store.as_ref().map(|p| p.to_str()).flatten();
        if self.password.is_none() {
            return Err(WalletError::Other("password is required".to_string()));
        }
        let pass = self.password.as_deref().unwrap_or("");
        let mut wallet = Wallet::open(StoreFile::default(path), pass).unwrap();

        let didopt = didopt.map(|m| m.to_wallet_options(did).unwrap());
        if wallet
            .unlock(pass, self.index.unwrap_or(0), didopt)
            .await
            .is_ok()
        {
            println!("unlock succeeded");
            return Ok(wallet);
        } else {
            println!("unlock failed");
            return Err(WalletError::Locked);
        }
    }
    pub fn lock(&self) -> Result<(), WalletError> {
        Ok(())
    }
}

#[derive(Subcommand, Debug, Clone)]
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
    Export {},

    /// Unlock vault and derive identity for this session
    //     Unlock {
    //         #[arg(long)]
    //         password: String,
    //         /// BIP44 account index (MetaMask path m/44'/60'/0'/0/{index})
    //         #[arg(long, default_value_t = 0)]
    //         index: u32,
    //         /// DID method: `key` (default) or `web` (requires --did)
    //         #[arg(long, value_enum, default_value_t = DidMethodArg::Key)]
    //         method: DidMethodArg,
    //         /// Full DID for `did:web` (e.g. did:web:example.com:user:alice)
    //         #[arg(long)]
    //         did: Option<String>,
    //     },
    //
    //     /// Clear unlocked session material
    //     Lock {
    //         #[arg(long)]
    //         password: String,
    //     },

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

#[derive(Subcommand, Debug, Clone)]
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

#[derive(Subcommand, Debug, Clone)]
pub enum DidCmd {
    /// Resolve / return the current DID document
    Resolve {
        #[arg(long)]
        did_buf: Option<String>,
        #[arg(long)]
        index: Option<u32>,
    },
    /// Prove control of the DID (challenge → JWS)
    Authenticate {
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        domain: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
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

#[derive(Subcommand, Debug, Clone)]
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
pub async fn run(mut cli: Cli) -> Result<(), String> {
    //let mut wallet = cli.unlock(None, None).await.unwrap();
    //let mut wallet: Wallet<StoreFile>;
    let mut cl = cli.clone();
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
                    "original password"
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
        Commands::Export {} => {
            let wallet = cli.unlock(None, None).await.unwrap();
            let mnemonic = wallet.mnemonic().unwrap();
            println!("{mnemonic}");
        }
        Commands::Status => {
            println!("[stub] status store={:?}", cli.store);
        }
        Commands::Card(ref cmd) => match cmd {
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
            DidCmd::Resolve { did_buf, index } => {
                let mut typer = did_buf.as_deref().unwrap_or("did:key");
                typer = &typer[..7];
                let index = index.unwrap_or(0);
                let mut wallet = cl.unlock(None, None).await.unwrap();
                match typer {
                    "did:web" => {
                        //let opt = DIDOptions::Web(Some(did.to_string()));
                        let opt = DIDOptions::Web(did_buf.clone());
                        wallet
                            .unlock(&cli.password.unwrap().split_off(0), index, Some(opt))
                            .await
                            .unwrap();
                        let request = DidRequest::ResolveDid {};
                        let response: DidResponse = wallet.handle(request).await.unwrap();
                        println!(
                            "[stub] did resolve did={did_buf:?} index={index:?} response={response:?}",
                        );
                    }
                    _ => {
                        let opt = DIDOptions::Key {};
                        wallet
                            .unlock(&cli.password.unwrap().split_off(0), index, Some(opt))
                            .await
                            .unwrap();
                        let request = DidRequest::ResolveDid {};
                        let response: DidResponse = wallet.handle(request).await.unwrap();
                        println!(
                            "[stub] did resolve did={did_buf:?} index={index:?} response={response:?}"
                        );
                    }
                }
            }
            DidCmd::Authenticate { challenge, domain } => {
                let request = Authenticate { challenge, domain };
                let wallet = cl.clone().unlock(None, None).await.unwrap();
                let signed_claims = wallet.handle(request).await.unwrap();
                println!("[stub] did authenticate signed={signed_claims:?}");
            }
        },
        Commands::Sign(cmd) => match cmd {
            SignCmd::Claims { json, file } => {
                if let Some(json_str) = json {
                    let request = DidRequest::SignClaims {
                        claims: serde_json::json!(json_str),
                    };
                    let wallet = cl.clone().unlock(None, None).await.unwrap();
                    let signed_claims = wallet.handle(request).await.unwrap();
                    println!(
                        "[stub] sign claims json={json_str:?} file={file:?} signed={signed_claims:?}"
                    );
                }

                if let Some(file_path) = file {
                    let json_str = std::fs::read_to_string(&file_path).unwrap();
                    let request = DidRequest::SignClaims {
                        claims: serde_json::json!(json_str),
                    };
                    let wallet = cl.clone().unlock(None, None).await.unwrap();
                    let signed_claims = wallet.handle(request).await.unwrap();
                    println!(
                        "[stub] sign claims json={json_str:?} file={file_path:?} signed={signed_claims:?}"
                    );
                }
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
