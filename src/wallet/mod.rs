use crate::keystore::{KeyVault, Store};
use bip39::{Language, Mnemonic, WordCount};
use rand::RngExt;
use ssi::prelude::*;
use std::str::FromStr;

#[derive(Debug, Default, Clone)]
struct Wallet<S: Store> {
    mnemonic: KeyVault<S>,
}

fn default_password_generate() -> Result<String, Box<dyn std::error::Error>> {
    use rand::rng;

    fn generate_password(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789\
                                )(*&^%$#@!~";
        let mut rng = rng();
        (0..length)
            .map(|_| {
                //let idx = rng.gen_range(0..CHARSET.len());
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
    let pwd = generate_password(16);
    println!("Generated password: {}", pwd);
    Ok(pwd)
}

trait WalletTrait<S: Store> {
    fn new(store: S, password: Option<&str>) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized;
    fn init(&mut self, mnemonic_str: &str, password: Option<&str>) -> Result<(), u16>;
    // fn sign(&self, data: &[u8]) -> Signature;
    // fn verify(&self, data: &[u8], signature: &Signature) -> bool;
    // fn get_public_key(&self) -> PublicKey;
    // fn get_address(&self) -> Address;
}

impl<S: Store> WalletTrait<S> for Wallet<S> {
    fn new(store: S, password: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize the mnemonic using the store
        let mnemonic = Mnemonic::generate_in(Language::English, WordCount::Words12)?;
        let password = match password {
            Some(p) => p.to_string(),
            None => default_password_generate()?,
        };
        let mut keyvault = KeyVault::new(store);
        keyvault.save(&password, &mnemonic);

        let wallet = Wallet { mnemonic: keyvault };
        Ok(wallet)
    }

    fn init(&mut self, mnemonic_str: &str, password: Option<&str>) -> Result<(), u16> {
        let mnemonic = Mnemonic::from_str(mnemonic_str);
        if password.is_none() {
            let ps = default_password_generate();
            self.mnemonic.save(&ps.unwrap(), &mnemonic.unwrap());
            return Ok(());
        }
        self.mnemonic.save(password.unwrap(), &mnemonic.unwrap());
        Ok(())
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
}
