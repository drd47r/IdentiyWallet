use crate::keystore::{KeyVault, Store};
use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic, WordCount};
use rand::RngExt;
use serde_json::json;
use ssi_jws::JwsPayload;
use std::str::FromStr;

mod didcard;
use didcard::*;

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

/// Which DID method to bind on unlock.
///
/// Primary supported methods: [`DIDOptions::Key`] (`did:key`) and
/// [`DIDOptions::Web`] (`did:web`). `Jwk` / `Eth` are optional extras.
#[derive(Debug, Clone)]
pub enum DIDOptions {
    /// `did:web:...` — pass the full DID string (document is local overlay + key).
    Web(Option<String>),
    Eth(Option<String>),
    Jwk,
    /// `did:key:...` derived from the public key (default).
    Key,
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
    //println!("Generated password: \n {}", pwd);
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
    fn open(store: S, password: &str) -> Result<Self, WalletError>;
    fn init(&mut self, mnemonic_str: &str, password: Option<&str>) -> Result<String, WalletError>;
    async fn unlock(
        &mut self,
        password: &str,
        index: u32,
        opt: Option<DIDOptions>,
    ) -> Result<(), WalletError>;
    fn lock(&mut self);
    fn card(&self) -> Result<&DidCard, WalletError>;
    fn mnemonic(&self) -> Result<Mnemonic, WalletError>;
    fn public_jwk(&self) -> Result<ssi::JWK, WalletError>;
    fn update_card(&mut self, patch: DidCardUpdate) -> Result<&DidCard, WalletError>;
    async fn handle(&self, request: DidRequest) -> Result<DidResponse, WalletError>;
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

    fn open(store: S, password: &str) -> Result<Self, WalletError> {
        let mut vault = KeyVault::new(store);
        let _mnemonic = vault.load(password);
        Ok(Wallet {
            vault,
            unlocked: None,
        })
    }

    fn init(&mut self, mnemonic_str: &str, password: Option<&str>) -> Result<String, WalletError> {
        let mnemonic = Mnemonic::from_str(mnemonic_str).map_err(|_| WalletError::Bip39)?;
        let password = match password {
            Some(p) => p.to_string(),
            None => default_password_generate()?,
        };
        self.vault
            .save(&password, &mnemonic)
            .map_err(|_| WalletError::Store)?;
        self.unlocked = None;
        Ok(password)
    }

    async fn unlock(
        &mut self,
        password: &str,
        index: u32,
        opt: Option<DIDOptions>,
    ) -> Result<(), WalletError> {
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

        let opt = opt.unwrap_or(DIDOptions::Key);
        let public = jwk.to_public();
        let (did, attach_jwk) = match opt {
            DIDOptions::Key => {
                let did = ssi::dids::DIDKey::generate(&public)
                    .map_err(|e| WalletError::Other(format!("did:key generate: {e}")))?;
                (did, None)
            }
            DIDOptions::Jwk => (ssi::dids::DIDJWK::generate(&public), None),
            DIDOptions::Web(did_string) => {
                let did_string = did_string.ok_or_else(|| {
                    WalletError::Other(
                        "did:web requires a DID string (e.g. did:web:example.com)".into(),
                    )
                })?;
                if !did_string.starts_with("did:web:") {
                    return Err(WalletError::Other(format!(
                        "expected did:web:..., got {did_string}"
                    )));
                }
                let did = ssi_dids::DIDBuf::from_string(did_string)
                    .map_err(|e| WalletError::Other(format!("invalid did:web: {e:?}")))?;
                (did, Some(public))
            }
            DIDOptions::Eth(_) => {
                return Err(WalletError::Other(
                    "did:ethr is not supported yet; use did:key or did:web".into(),
                ));
            }
        };
        let card = DidCard::new(did, attach_jwk).await;
        self.unlocked = Some(Unlocked {
            mnemonic,
            jwk,
            card,
        });
        Ok(())
    }

    fn lock(&mut self) {
        self.unlocked = None;
    }

    fn card(&self) -> Result<&DidCard, WalletError> {
        self.unlocked
            .as_ref()
            .map(|u| &u.card)
            .ok_or(WalletError::Locked)
    }

    fn mnemonic(&self) -> Result<Mnemonic, WalletError> {
        self.unlocked
            .as_ref()
            .map(|u| u.mnemonic.clone())
            .ok_or(WalletError::Locked)
    }

    fn public_jwk(&self) -> Result<ssi::JWK, WalletError> {
        self.unlocked
            .as_ref()
            .map(|u| u.jwk.to_public())
            .ok_or(WalletError::Locked)
    }

    fn update_card(&mut self, patch: DidCardUpdate) -> Result<&DidCard, WalletError> {
        let unlocked = self.unlocked.as_mut().ok_or(WalletError::Locked)?;

        // Local overlay only: never touch unlocked.card.did / document.id.
        if let Some(label) = patch.label {
            unlocked.card.label = Some(label);
        }
        if let Some(also_known_as) = patch.also_known_as {
            unlocked.card.document.also_known_as = also_known_as
                .into_iter()
                .map(|s| {
                    iref::IriBuf::new(s)
                        .map_err(|e| WalletError::Other(format!("invalid alsoKnownAs IRI: {e}")))
                })
                .collect::<Result<Vec<_>, _>>()?;
        }
        if let Some(services) = patch.services {
            unlocked.card.document.service = services;
        }

        Ok(&unlocked.card)
    }

    async fn handle(&self, _request: DidRequest) -> Result<DidResponse, WalletError> {
        self.unlocked.as_ref().ok_or(WalletError::Locked)?;
        //todo!("ResolveDid / Authenticate / SignClaims")
        let unlocked = self.unlocked.as_ref().unwrap();
        match _request {
            DidRequest::ResolveDid => Ok(DidResponse::Document(unlocked.card.document.clone())),
            DidRequest::Authenticate { challenge, domain } => {
                let payload = json!({
                    "did": unlocked.card.did.as_str(),
                    "challenge": challenge,
                    "domain": domain
                });
                let signbuff = payload
                    .to_string()
                    .sign(&unlocked.jwk)
                    .await
                    .map_err(|e| WalletError::Other(e.to_string()))?;
                Ok(DidResponse::Jws(signbuff))
            }
            DidRequest::SignClaims { claims } => {
                let signbuff = claims
                    .to_string()
                    .sign(&unlocked.jwk)
                    .await
                    .map_err(|e| WalletError::Other(e.to_string()))?;
                Ok(DidResponse::Jws(signbuff))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::StoreFile;

    #[test]
    fn test_wallet_new() {
        let wallet = Wallet::new(StoreFile::default(None), None);
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
    async fn test_wallet_unlock_did_key() {
        let mut wallet = Wallet::new(StoreFile::default(None), Some("password")).unwrap();
        let mnemonic = Mnemonic::generate_in(Language::English, WordCount::Words12).unwrap();
        wallet
            .init(&mnemonic.to_string(), Some("password"))
            .unwrap();
        wallet
            .unlock("password", 0, Some(DIDOptions::Key))
            .await
            .unwrap();
        let did = wallet.card().unwrap().did.as_str();
        assert!(did.starts_with("did:key:"), "expected did:key, got {did}");
    }

    #[tokio::test]
    async fn test_wallet_unlock_did_web() {
        let mut wallet = Wallet::new(StoreFile::default(None), Some("password")).unwrap();
        let mnemonic = Mnemonic::generate_in(Language::English, WordCount::Words12).unwrap();
        wallet
            .init(&mnemonic.to_string(), Some("password"))
            .unwrap();
        let web = "did:web:example.com:user:alice".to_owned();
        wallet
            .unlock("password", 0, Some(DIDOptions::Web(Some(web.clone()))))
            .await
            .unwrap();
        assert_eq!(wallet.card().unwrap().did.as_str(), web);
        assert!(
            !wallet
                .card()
                .unwrap()
                .document
                .verification_method
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_wallet_resolve_did_authenticate_handle() {
        //create a wallet and unlock it
        let mut wallet = Wallet::new(StoreFile::default(None), Some("password")).unwrap();
        let mnemonic = Mnemonic::generate_in(Language::English, WordCount::Words12).unwrap();
        let result = wallet.init(&mnemonic.to_string(), Some("password"));
        assert!(result.is_ok());
        assert!(wallet.unlock("password", 0, None).await.is_ok());

        // test resolve did request
        let request = DidRequest::ResolveDid;
        let response = wallet.handle(request).await.unwrap();
        println!(
            "ResolveDid respone \n {:?}",
            if let DidResponse::Document(doc) = response {
                println!("{:#?}", doc)
            }
        );
        // test authenticate request
        let request = DidRequest::Authenticate {
            challenge: "this is challenge".to_string(),
            domain: Some("example.com".to_string()),
        };

        let response = wallet.handle(request).await.unwrap();
        println!("Auth respone \n {:?}", &response);

        // test public jwk
        let jwk = wallet.public_jwk().unwrap();
        let DidResponse::Jws(jws_buff) = response else {
            panic!("expected Jws response")
        };

        // test jws verification
        let jws = ssi_jws::Jws::from_str_const(jws_buff.as_str()).unwrap();
        assert!(jws.verify(&jwk).await.is_ok());
    }

    #[tokio::test]
    async fn test_wallet_sign_claims_handle() {
        let mut wallet = Wallet::new(StoreFile::default(None), Some("password")).unwrap();
        let mnemonic = Mnemonic::generate_in(Language::English, WordCount::Words12).unwrap();
        let result = wallet.init(&mnemonic.to_string(), Some("password"));
        assert!(result.is_ok());
        assert!(wallet.unlock("password", 0, None).await.is_ok());
        // test sign claims request
        let request = DidRequest::SignClaims {
            claims: serde_json::json!({}),
        };
        let response = wallet.handle(request).await.unwrap();
        println!("SignClaims respone \n {:?}", &response);
    }

    #[tokio::test]
    async fn test_wallet_update_card() {
        let mut wallet = Wallet::new(StoreFile::default(None), Some("password")).unwrap();
        let mnemonic = Mnemonic::generate_in(Language::English, WordCount::Words12).unwrap();
        wallet
            .init(&mnemonic.to_string(), Some("password"))
            .unwrap();
        wallet.unlock("password", 0, None).await.unwrap();

        let did_before = wallet.card().unwrap().did.clone();
        let card = wallet
            .update_card(DidCardUpdate {
                label: Some("alice".into()),
                also_known_as: Some(vec!["https://example.com/alice".into()]),
                services: None,
            })
            .unwrap();

        assert_eq!(card.label.as_deref(), Some("alice"));
        assert_eq!(card.did, did_before);
        assert_eq!(card.document.id, did_before);
        assert_eq!(
            card.document.also_known_as[0].as_str(),
            "https://example.com/alice"
        );
    }

    #[tokio::test]
    async fn test_wallet_request_card_handle() {
        let mut wallet = Wallet::new(StoreFile::default(None), Some("password")).unwrap();
        let mnemonic = Mnemonic::generate_in(Language::English, WordCount::Words12).unwrap();
        let result = wallet.init(&mnemonic.to_string(), Some("password"));
        assert!(result.is_ok());
        let opt = DIDOptions::Web(Some("did:web:w3c-ccg.github.io:user:alice".to_owned()));
        assert!(wallet.unlock("password", 0, Some(opt)).await.is_ok());
        let card = wallet.card().unwrap();
        println!("Did Card document \n{:#?}", &card.document);
        // test sign claims request
        let request = DidRequest::ResolveDid {};
        let response = wallet.handle(request).await.unwrap();
        println!("SignClaims respone \n{:?}", &response);
    }
}
