use std::str::FromStr;
//Store BIP39 Mnemonic to encrypted file
use argon2::{Argon2, password_hash::generate_salt};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, Generate, KeyInit},
};

pub type Mnemonic = Vec<String>;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

pub trait Store {
    fn read(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn write(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>>;
}

#[derive(Default, Clone, Debug)]
pub struct StoreMemory {
    bytes: Vec<u8>,
}

impl Store for StoreMemory {
    fn read(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.bytes.clone())
    }
    fn write(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.bytes = data.to_vec();
        Ok(())
    }
}

#[derive(Default, Clone, Debug)]
pub struct StoreFile {
    path: std::path::PathBuf,
}
impl StoreFile {
    pub fn default(path_str: Option<&str>) -> Self {
        Self {
            path: std::path::PathBuf::from_str(path_str.unwrap_or("/tmp/keystore.ebin")).unwrap(),
        }
    }
}
impl Store for StoreFile {
    fn read(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(std::fs::read(&self.path)?)
    }
    fn write(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        std::fs::write(&self.path, data)?;
        Ok(())
    }
}

pub trait KeyStoreTrait {
    fn _encrypt(
        &self,
        password: &str,
        mnemonic: &Mnemonic,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let salt = generate_salt();
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|e| format!("Argon2 KDF error: {e}"))?;

        let cipher = ChaCha20Poly1305::new(&Key::from(key));
        let nonce = Nonce::generate();
        let ciphertext = cipher
            .encrypt(&nonce, mnemonic.join(" ").as_bytes())
            .map_err(|e| format!("Encryption error: {e}"))?;

        let mut bytes = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(nonce.as_slice());
        bytes.extend_from_slice(&ciphertext);
        Ok(bytes)
    }

    fn _decrypt(
        &self,
        password: &str,
        encrypted_bytes: &[u8],
    ) -> Result<Mnemonic, Box<dyn std::error::Error>> {
        if encrypted_bytes.len() < SALT_LEN + NONCE_LEN {
            return Err("Encrypted data is too short".into());
        }

        let salt = &encrypted_bytes[..SALT_LEN];
        let nonce = Nonce::try_from(&encrypted_bytes[SALT_LEN..SALT_LEN + NONCE_LEN])?;
        let ciphertext = &encrypted_bytes[SALT_LEN + NONCE_LEN..];

        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| format!("Argon2 KDF error: {e}"))?;

        let cipher = ChaCha20Poly1305::new(&Key::from(key));
        let decrypted = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| format!("Decryption error: {e}"))?;

        let mnemonic_str = String::from_utf8(decrypted)?;
        let mnemonic = mnemonic_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect::<Mnemonic>();
        Ok(mnemonic)
    }
}

#[derive(Default, Clone, Debug)]
pub struct KeyVault<S: Store> {
    pub store: Option<S>,
}

impl<S: Store> KeyVault<S> {
    pub fn new(store: S) -> Self {
        Self { store: Some(store) }
    }

    fn save(
        &mut self,
        password: &str,
        mnemonic: &Mnemonic,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = self._encrypt(password, mnemonic)?;
        match self.store {
            Some(ref mut store) => {
                store.write(&bytes)?;
                return Ok(());
            }
            None => {
                return Err("No store provided".into());
            }
        };
    }

    fn load(&mut self, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        let bytes = match self.store {
            Some(ref store) => store.read()?,
            None => {
                return Err("No store provided".into());
            }
        };
        let mnemonic = self._decrypt(password, &bytes)?;
        Ok(mnemonic.join(" ").to_string())
    }
}

impl<S: Store> KeyStoreTrait for KeyVault<S> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_load() {
        let store = StoreMemory::default();
        let mut mnemonicstore = KeyVault::new(store);
        let mnemonic: Mnemonic = vec!["slite".to_string(), "test".to_string(), "rust".to_string()];
        mnemonicstore
            .save("password", &mnemonic)
            .expect("some thing happend");

        let loaded = mnemonicstore.load("password").unwrap();
        println!("loaded string is {:?}", &loaded);
        assert_eq!(loaded, mnemonic.join(" ").to_string());
    }

    #[test]
    fn test_wrong_password_fails() {
        let store = StoreMemory::default();
        let mut mnemonicstore = KeyVault::new(store);
        let mnemonic: Mnemonic = vec!["slite".to_string(), "test".to_string(), "rust".to_string()];
        mnemonicstore
            .save("password", &mnemonic)
            .expect("error in save");
        let loaded = mnemonicstore.load("wrong_password");
        assert!(loaded.is_err());
    }

    #[test]
    fn test_storefile_save_load() {
        let store = StoreFile::default(None);
        let mut mnemonicstore = KeyVault::new(store);
        let mnemonic: Mnemonic = vec!["slite".to_string(), "test".to_string(), "rust".to_string()];
        mnemonicstore
            .save("password", &mnemonic)
            .expect("error in save");
        let loaded = mnemonicstore.load("password").unwrap();
        assert_eq!(loaded, mnemonic.join(" ").to_string());
    }

    #[test]
    fn test_storefile_save_load_with_path() {
        let store = StoreFile::default(Some("/tmp/keystore_test.ebin"));
        let mut mnemonicstore = KeyVault::new(store);
        let mnemonic: Mnemonic = vec!["slite".to_string(), "test".to_string(), "rust".to_string()];
        mnemonicstore
            .save("password", &mnemonic)
            .expect("error in save");
        let loaded = mnemonicstore.load("password").unwrap();
        assert_eq!(loaded, mnemonic.join(" ").to_string());
    }
}
