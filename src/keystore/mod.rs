//Store BIP39 Mnemonic to encrypted file
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, phc::SaltString},
};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};

type Mnemonic = Vec<String>;

trait KeyStoreTrait {
    fn save(
        &mut self,
        password: &str,
        mnemonic: &Mnemonic,
    ) -> Result<(), Box<dyn std::error::Error>>;
    fn load(&mut self, password: &str) -> Result<String, Box<dyn std::error::Error>>;
    fn _encrypt(&self, password: &str, mnemonic: &Mnemonic) -> Vec<u8> {
        let salt = SaltString::generate();
        let argon2 = Argon2::default();
        let pass_hash = argon2.hash_password(password.as_bytes()).unwrap();
        let mut bytes = pass_hash.to_string().as_bytes().to_vec();

        let cipher = ChaCha20Poly1305::new(&Key::from_slice(&bytes));
        let nonce = Nonce::from_slice(&salt.as_bytes());
        let encrypted = cipher
            .encrypt(&nonce, mnemonic.join(" ").as_bytes())
            .unwrap();
        bytes.extend(encrypted);
        bytes
    }
    fn _decrypt(
        &self,
        password: &str,
        bytes: &[u8],
    ) -> Result<Mnemonic, Box<dyn std::error::Error>> {
        let salt = SaltString::generate();
        let argon2 = Argon2::default();
        let pass_hash = argon2.hash_password(password.as_bytes()).unwrap();
        let mut bytes = pass_hash.to_string().as_bytes().to_vec();

        let cipher = ChaCha20Poly1305::new(&Key::from_slice(&bytes));
        let nonce = Nonce::from_slice(&salt.as_bytes());
        let payload = &bytes[32..];
        let decrypted = cipher.decrypt(&nonce, payload).unwrap();
        let mnemonic: Mnemonic = String::from_utf8(decrypted)
            .unwrap()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        Ok(mnemonic)
    }
}

// #[derive(Debug, Clone)]
// pub struct KeyStoreFile {
//     path: std::path::PathBuf,
//     bytes: Vec<u8>,
// }

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
        self.bytes = self._encrypt(password, mnemonic);
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

// impl KeyStoreTrait for KeyStoreFile {
//     fn save(
//         &mut self,
//         password: &str,
//         mnemonic: &Mnemonic,
//     ) -> Result<(), Box<dyn std::error::Error>> {
//         self.bytes = self._encrypt(password, mnemonic);
//         std::fs::write(&self.path, &self.bytes)?;
//         Ok(())
//     }
//
//     fn load(&mut self, password: &str) -> Result<String, Box<dyn std::error::Error>> {
//         self.bytes = std::fs::read(&self.path)?;
//         let mnemonic = self._decrypt(password, &self.bytes)?;
//         Ok(mnemonic.join(" ").to_string())
//     }
// }

#[cfg(test)]
mod tests {
    use crate::keystore::KeyStoreMemory;
    use crate::keystore::KeyStoreTrait;
    use crate::keystore::Mnemonic;

    #[test]
    fn test_save_load() {
        let mut keystore = crate::keystore::KeyStoreMemory::default();
        let mnemonic = crate::keystore::Mnemonic::default();
        keystore.save("", &mnemonic).unwrap();
        let loaded = keystore.load("").unwrap();
        assert_eq!(loaded, mnemonic.join(" ").to_string());
    }
}
