use crate::keystore::{KeyVault, Store};
use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic, WordCount};
use rand::RngExt;
use ssi::dids::AnyDidMethod;
use ssi::prelude::*;
use std::str::FromStr;

/// DID identity card shown to the agent.
///
/// For `did:jwk` / `did:key`, `did` is derived from the key. `label` and later
/// document overlay fields are local only.
#[derive(Debug, Clone)]
pub struct DidCard {
    pub did: ssi::dids::DIDBuf,
    pub document: ssi::dids::Document,
    pub label: Option<String>,
}

impl DidCard {
    pub async fn new(did: ssi::dids::DIDBuf) -> Self {
        let resolver = AnyDidMethod::default();
        let did_doc = resolver.resolve(&did).await.unwrap().document;
        Self {
            did,
            document: did_doc.into_document(),
            label: None,
        }
    }
}

/// Local-only patches to a [DidCard]. Does not rotate the DID.
#[derive(Debug, Clone, Default)]
pub struct DidCardUpdate {
    pub label: Option<String>,
    pub also_known_as: Option<Vec<String>>,
    pub services: Option<Vec<ssi::dids::document::Service>>,
}

/// Requests a system / agent can send the wallet.
#[derive(Debug, Clone)]
pub enum DidRequest {
    ResolveDid,
    Authenticate {
        challenge: String,
        domain: Option<String>,
    },
    SignClaims {
        claims: serde_json::Value,
    },
}

#[derive(Debug, Clone)]
pub enum DidResponse {
    Document(ssi::dids::Document),
    Jws(ssi::claims::JwsBuf),
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("wallet is locked")]
    Locked,
    #[error("store error")]
    Store,
    #[error("decrypt error")]
    Decrypt,
    #[error("bip39 error")]
    Bip39,
    #[error("bip32 error")]
    Bip32,
    #[error("ssi error")]
    Ssi,
    #[error("{0}")]
    Other(String),
}

/// Unlocked session material. Fill in on `unlock` / after `new`+derive:
/// 1. `mnemonic.to_seed("")`
/// 2. BIP32 master `XPrv` at path `m` (secp256k1)
/// 3. `ssi::JWK` then `DIDJWK::generate(&jwk.to_public())`
#[derive(Debug, Clone)]
struct Unlocked {
    #[allow(dead_code)]
    mnemonic: Mnemonic,
    #[allow(dead_code)]
    jwk: ssi::JWK,
    #[allow(dead_code)]
    card: DidCard,
}

#[derive(Debug, Default, Clone)]
pub struct Wallet<S: Store> {
    vault: KeyVault<S>,
    unlocked: Option<Unlocked>,
}

fn default_password_generate() -> Result<String, WalletError> {
    use rand::rng;

    fn generate_password(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789\
                                )(*&^%$#@!~";
        let mut rng = rng();
        (0..length)
            .map(|_| {
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
    let pwd = generate_password(16);
    println!("Generated password: {}", pwd);
    Ok(pwd)
}

pub fn metamask_account(seed: &[u8], index: u32) -> Result<XPrv, WalletError> {
    let path: DerivationPath = format!("m/44'/60'/0'/0/{index}")
        .parse()
        .map_err(|_| WalletError::Bip32)?;
    XPrv::derive_from_path(seed, &path).map_err(|_| WalletError::Bip32)
}

#[allow(async_fn_in_trait)]
pub trait WalletTrait<S: Store>: Sized {
    fn new(store: S, password: Option<&str>) -> Result<Self, WalletError>;
    fn init(&mut self, mnemonic_str: &str, password: Option<&str>) -> Result<(), WalletError>;
    async fn unlock(&mut self, password: &str, index: u32) -> Result<(), WalletError>;
    fn lock(&mut self);
    fn card(&self) -> Result<&DidCard, WalletError>;
    fn public_jwk(&self) -> Result<ssi::JWK, WalletError>;
    fn update_card(&mut self, patch: DidCardUpdate) -> Result<&DidCard, WalletError>;
    fn handle(&self, request: DidRequest) -> Result<DidResponse, WalletError>;
}

impl<S: Store> WalletTrait<S> for Wallet<S> {
    fn new(store: S, password: Option<&str>) -> Result<Self, WalletError> {
        let mnemonic = Mnemonic::generate_in(Language::English, WordCount::Words12)
            .map_err(|_| WalletError::Bip39)?;
        let password = match password {
            Some(p) => p.to_string(),
            None => default_password_generate()?,
        };
        let mut vault = KeyVault::new(store);
        vault
            .save(&password, &mnemonic)
            .map_err(|_| WalletError::Store)?;

        Ok(Wallet {
            vault,
            unlocked: None,
        })
    }

    fn init(&mut self, mnemonic_str: &str, password: Option<&str>) -> Result<(), WalletError> {
        let mnemonic = Mnemonic::from_str(mnemonic_str).map_err(|_| WalletError::Bip39)?;
        let password = match password {
            Some(p) => p.to_string(),
            None => default_password_generate()?,
        };
        self.vault
            .save(&password, &mnemonic)
            .map_err(|_| WalletError::Store)?;
        self.unlocked = None;
        Ok(())
    }

    async fn unlock(&mut self, password: &str, index: u32) -> Result<(), WalletError> {
        // load mnemonic from vault, then:
        // mnemonic.to_seed("") -> BIP32 account at m/44'/60'/0'/0/{index}
        // -> ssi::JWK -> DIDJWK::generate(&jwk)
        let mnemonic = self
            .vault
            .load(password)
            .map_err(|_| WalletError::Decrypt)?;
        let seed = mnemonic.to_seed("");
        let private_key = metamask_account(&seed, index)?;
        // XPrv::to_bytes() is a raw 32-byte scalar. ssi's k256 (0.13) is a
        // different crate from bip32's k256 (0.14), so parse the bytes with
        // ssi's type. secp256k1_parse_private expects SEC1 DER, not raw bytes.
        let secret = ssi::crypto::k256::SecretKey::from_slice(&private_key.to_bytes())
            .map_err(|_| WalletError::Ssi)?;
        let jwk = ssi::JWK::from(ssi::jwk::Params::EC(ssi::jwk::ECParams::from(&secret)));
        let did = ssi::dids::DIDJWK::generate(&jwk);
        let card = DidCard::new(did).await;
        self.unlocked = Some(Unlocked { mnemonic, jwk, card });
        Ok(())
    }

    fn lock(&mut self) {
        self.unlocked = None;
    }

    fn card(&self) -> Result<&DidCard, WalletError> {
        todo!("return unlocked card")
    }

    fn public_jwk(&self) -> Result<ssi::JWK, WalletError> {
        todo!("JWK::to_public, never private")
    }

    fn update_card(&mut self, _patch: DidCardUpdate) -> Result<&DidCard, WalletError> {
        todo!("local overlay only")
    }

    fn handle(&self, _request: DidRequest) -> Result<DidResponse, WalletError> {
        todo!("ResolveDid / Authenticate / SignClaims")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::StoreFile;

    #[test]
    fn test_wallet_new() {
        let wallet = Wallet::new(StoreFile::default(None), Some("password"));
        assert!(wallet.is_ok());
    }
    #[test]
    fn test_wallet_init() {
        let mut wallet = Wallet::new(StoreFile::default(None), Some("password")).unwrap();
        let mnemonic = Mnemonic::generate_in(Language::English, WordCount::Words12).unwrap();
        let result = wallet.init(&mnemonic.to_string(), Some("password"));
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wallet_master_key() {
        let mut wallet = Wallet::new(StoreFile::default(None), Some("password")).unwrap();
        let mnemonic = Mnemonic::generate_in(Language::English, WordCount::Words12).unwrap();
        let result = wallet.init(&mnemonic.to_string(), Some("password"));
        assert!(result.is_ok());
        assert!(wallet.unlock("password", 0).await.is_ok());
    }
}
