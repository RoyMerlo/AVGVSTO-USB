use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};

pub struct AuthEngine;

impl AuthEngine {
    /// Hashes a new administrator password for offline vault locking.
    pub fn hash_password(password: &str) -> Result<String, String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| format!("Hashing failed: {}", e))?
            .to_string();
            
        Ok(password_hash)
    }

    /// Verifies the entered password against the stored Argon2 hash.
    pub fn verify_password(password: &str, stored_hash: &str) -> bool {
        let parsed_hash = match PasswordHash::new(stored_hash) {
            Ok(hash) => hash,
            Err(_) => return false,
        };
        let argon2 = Argon2::default();
        argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok()
    }
}
