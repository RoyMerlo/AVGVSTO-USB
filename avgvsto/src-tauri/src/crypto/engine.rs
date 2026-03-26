use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use rand::RngCore;

pub struct CryptoMaster;

impl CryptoMaster {
    /// Encrypts data using AES-256-GCM.
    /// Returns a tuple of (nonce, ciphertext)
    pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; 12 bytes
        
        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|e| format!("Encryption failure: {}", e))?;
            
        Ok((nonce.to_vec(), ciphertext))
    }

    /// Decrypts AES-256-GCM encrypted data.
    pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(nonce);
        
        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failure: Invalid key or corrupted data".to_string())
    }

    /// Generates a secure random 256-bit key
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }
}
