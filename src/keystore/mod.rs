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

pub trait KeyStoreTrait {
    fn save(
        &mut self,
        password: &str,
        mnemonic: &Mnemonic,
    ) -> Result<(), Box<dyn std::error::Error>>;

    fn load(&mut self, password: &str) -> Result<String, Box<dyn std::error::Error>>;

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

#[derive(Debug, Clone)]
pub struct KeyStoreMemory {
    bytes: Vec<u8>,
}

impl KeyStoreTrait for KeyStoreMemory {
    fn save(
        &mut self,
        password: &str,
        mnemonic: &Mnemonic,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.bytes = self._encrypt(password, mnemonic)?;
        Ok(())
    }

    fn load(&mut self, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mnemonic = self._decrypt(password, &self.bytes)?;
        Ok(mnemonic.join(" ").to_string())
    }
}

impl Default for KeyStoreMemory {
    fn default() -> Self {
        Self { bytes: Vec::new() }
    }
}

#[derive(Debug, Clone)]
pub struct KeyStoreFile {
    bytes: Vec<u8>,
    path: std::path::PathBuf,
}

impl Default for KeyStoreFile {
    fn default() -> Self {
        Self {
            bytes: Vec::new(),
            path: std::path::PathBuf::from_str("/tmp/keystore.ebin").unwrap(),
        }
    }
}

impl KeyStoreTrait for KeyStoreFile {
    fn save(
        &mut self,
        password: &str,
        mnemonic: &Mnemonic,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.bytes = self._encrypt(password, mnemonic)?;
        std::fs::write(&self.path, &self.bytes)?;
        Ok(())
    }

    fn load(&mut self, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.bytes = std::fs::read(&self.path)?;
        let mnemonic = self._decrypt(password, &self.bytes)?;
        Ok(mnemonic.join(" ").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_load() {
        let mut keystore = KeyStoreMemory::default();
        let mnemonic: Mnemonic = vec!["slite".to_string(), "test".to_string(), "rust".to_string()];
        keystore.save("password", &mnemonic).unwrap();
        let loaded = keystore.load("password").unwrap();
        assert_eq!(loaded, mnemonic.join(" ").to_string());
    }

    #[test]
    fn test_wrong_password_fails() {
        let mut keystore = KeyStoreMemory::default();
        let mnemonic: Mnemonic = vec!["slite".to_string(), "test".to_string(), "rust".to_string()];
        keystore.save("password", &mnemonic).unwrap();
        let result = keystore.load("wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_storefile_save_load() {
        let mut keystore = KeyStoreFile::default();
        let mnemonic: Mnemonic = vec!["slite".to_string(), "test".to_string(), "rust".to_string()];
        keystore.save("password", &mnemonic).unwrap();
        let loaded = keystore.load("password").unwrap();
        assert_eq!(loaded, mnemonic.join(" ").to_string());
    }
}
