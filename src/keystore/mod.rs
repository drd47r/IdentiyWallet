//Store BIP39 Mnemonic to encrypted file
use crate::crypto::Crypto::{decrypt, encrypt};

type Mnemonic = Vec<String>;

trait KeyStoreTrait {
    fn save(&self, password: &str, mnemonic: &Mnemonic) -> Result<(), Box<dyn std::error::Error>>;
    fn load(&self, password: &str) -> Result<String, Box<dyn std::error::Error>>;
    fn _encrypt(&self, password: &str, mnemonic: &Mnemonic) -> Vec<u8> {
        Crypto::encrypt(password, mnemonic)
    }
    fn _decrypt(
        &self,
        password: &str,
        bytes: &[u8],
    ) -> Result<Mnemonic, Box<dyn std::error::Error>> {
        Crypto::decrypt(password, bytes)
    }
}

#[derive(Debug, Clone)]
pub struct KeyStoreFile {
    path: std::path::PathBuf,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct KeyStoreMemory {
    bytes: Vec<u8>,
}

impl KeyStoreTrait for KeyStoreMemory {
    fn save(&self, password: &str, mnemonic: &Mnemonic) -> Result<(), Box<dyn std::error::Error>> {
        self.bytes = self._encrypt(password, mnemonic);
        Ok(())
    }

    fn load(&self, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mnemonic = self._decrypt(password, &self.bytes)?;
        Ok()
    }
}

impl KeyStoreTrait for KeyStoreFile {
    fn save(&self, password: &str, mnemonic: &Mnemonic) -> Result<(), Box<dyn std::error::Error>> {
        self.bytes = self._encrypt(password, mnemonic);
        std::fs::write(&self.path, &self.bytes)?;
        Ok(())
    }

    fn load(&mut self, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.bytes = std::fs::read(&self.path)?;
        let mnemonic = self._decrypt(password, &self.bytes)?;
        Ok()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_save_load() {
        let keystore = KeyStoreMemory::default();
        let mnemonic = Mnemonic::default();
        keystore.save("", &mnemonic).unwrap();
        let loaded = keystore.load("").unwrap();
        assert_eq!(loaded, mnemonic.to_string());
    }
}
