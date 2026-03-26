use std::process::Command;

pub struct UsbManager;

impl UsbManager {
    /// Fingerprints a connected drive using its Volume ID and Serial Number.
    /// Returns a hardware signature hash.
    #[cfg(target_os = "windows")]
    pub fn get_drive_signature(drive_letter: &str) -> Result<String, String> {
        let output = Command::new("wmic")
            .args(&["logicaldisk", "where", &format!("caption='{}'", drive_letter), "get", "volumeserialnumber"])
            .output()
            .map_err(|e| format!("Failed to read USB: {}", e))?;
            
        let out_str = String::from_utf8_lossy(&output.stdout);
        let serial = out_str.lines().skip(1).find(|l| !l.trim().is_empty()).unwrap_or("").trim();
        
        if serial.is_empty() {
            return Err("No serial found for drive".to_string());
        }
        
        Ok(serial.to_string())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_drive_signature(mount_path: &str) -> Result<String, String> {
        // Fallback or Unix implementation
        // e.g., using `lsblk` or reading UUIDs on Linux/macOS
        Ok(format!("unix_vol_{}", mount_path))
    }
}
