use rusqlite::{Connection, Result};
use std::path::PathBuf;

pub struct SecureDatabase {
    pub conn: Connection,
}

impl SecureDatabase {
    /// Opens the SQLite connection and immediately applies the SQLCipher key.
    pub fn open(db_path: PathBuf, key: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        
        // Apply SQLCipher key PRAGMAs
        conn.execute(&format!("PRAGMA key = '{}';", key), [])?;
        conn.execute("PRAGMA cipher_page_size = 4096;", [])?;
        conn.execute("PRAGMA kdf_iter = 256000;", [])?;
        conn.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512;", [])?;
        
        // Verify we can read/write data (fails if key is wrong)
        conn.query_row("SELECT count(*) FROM sqlite_master;", [], |_| Ok(()))?;

        let db = SecureDatabase { conn };
        db.initialize_schema()?;
        
        Ok(db)
    }

    /// Creates all local tables required by the AVGVSTO offline enforcement strategy.
    fn initialize_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            -- Configuration and Local Admin Authentication
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY DEFAULT 1,
                business_name TEXT NOT NULL,
                auth_hash TEXT NOT NULL,
                salt BLOB,
                auth_disabled BOOLEAN DEFAULT 0
            );
            
            -- Immutable audit logs for compliance
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL
            );
            
            -- Registered hardware tokens (USB Fingerprints)
            CREATE TABLE IF NOT EXISTS usb_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hardware_id TEXT UNIQUE NOT NULL,
                alias TEXT NOT NULL
            );
            "
        )?;
        Ok(())
    }
}
