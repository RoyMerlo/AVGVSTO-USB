pub mod crypto;
pub mod db;
pub mod auth;
pub mod usb;

#[tauri::command]
fn hash_password(password: String) -> Result<String, String> {
    auth::engine::AuthEngine::hash_password(&password)
}

#[tauri::command]
fn verify_password(password: String, hash: String) -> bool {
    auth::engine::AuthEngine::verify_password(&password, &hash)
}

fn main() {
    tauri::Builder::default()
        .setup(|_app| {
            println!("AVGVSTO 4.0 // Initializing Secure Offline Daemon...");
            // Initialize logic here...
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            hash_password,
            verify_password
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
