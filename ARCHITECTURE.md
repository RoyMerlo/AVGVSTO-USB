# AVGVSTO - System Architecture

## 1. Core Objectives
- **Data Sovereignty:** 100% offline-first. Zero external API calls, no telemetry, no CDNs.
- **Impenetrable Security:** Encrypted local storage, hardware-bound (USB) capability, strict access control.
- **High Performance:** Lightweight, native-compiled executables for Windows, macOS, and Linux.
- **Professional UX:** Minimalist, dark-themed, "Godlike" highly responsive interface.

## 2. Technology Stack
- **Application Framework:** **Tauri (Rust)**
  - *Why:* Provides a memory-safe backend, native cross-platform compilation (.exe, .app, AppImage/deb), and strict system sandboxing without the heavy bloat and security pitfalls of Electron.
- **Frontend UI:** **React (via Vite) + Vanilla CSS**
  - *Why:* Component-driven structure for managing complex states (like the Setup Wizard). Vanilla CSS ensures strict adherence to non-CDN aesthetics, enabling a proprietary design system. All fonts, icons, and assets are bundled locally.
- **Database / Storage:** **SQLite + SQLCipher** (via `rusqlite` with `sqlcipher` bundled)
  - *Why:* Transparent AES-256 encryption of all application data at rest. Impossible to read the local DB without the master key.
- **Crypto & Security Logic:** **Rust native crypto (`argon2`, `aes-gcm`, `chacha20poly1305`)**
  - *Why:* High performance and memory-safe cryptography algorithms. Argon2 for auth hashing, AES-256-GCM / ChaCha20 for file and data operations.

## 3. Folder Structure
```text
avgvsto/
├── src-tauri/               # Rust Backend (100% Offline Logic)
│   ├── Cargo.toml
│   ├── build.rs             # SQLite/SQLCipher build configurations
│   ├── src/
│   │   ├── main.rs          # Application entry point
│   │   ├── auth.rs          # Startup authentication, Password hashing, & Backoff
│   │   ├── db.rs            # Encrypted SQLite connection management
│   │   ├── crypto.rs        # AES/ChaCha20 encryption logic
│   │   ├── usb_manager.rs   # Hardware fingerprinting & USB sandbox import
│   │   └── commands.rs      # IPC bridge endpoints for frontend
│   └── icons/               # Bundled app icons (.ico, .icns, .png)
├── src/                     # Frontend UI (React)
│   ├── assets/              # ALL local fonts, images (No CDNs)
│   ├── components/          # Reusable UI (Buttons, Modals, SecureInputs)
│   ├── pages/               # Views (SetupWizard, Dashboard, Settings)
│   ├── styles/              # Deep dark mode, minimalist visual DNA (Vanilla CSS)
│   ├── App.jsx
│   └── main.jsx
├── package.json
└── vite.config.js
```

## 4. Local Database Schema (SQLCipher)
**Storage location:** Platform-specific secure app data directory (e.g., `%APPDATA%\AVGVSTO\secure_vault.db`).

### Tables:
- **`config`**
  - `id` (PK)
  - `business_name` (Text)
  - `auth_hash` (Text, Argon2 password hash)
  - `salt` (Blob)
  - `auth_disabled` (Boolean, for disable toggle)
  
- **`audit_logs`**
  - `id` (PK)
  - `timestamp` (Integer)
  - `event_type` (Text)
  - `details` (Text)

- **`usb_devices`** (Registered USB Drives for hardware fingerprinting)
  - `id` (PK)
  - `hardware_id` (Text, Hash of Serial + VolumeID)
  - `alias` (Text, user-friendly name)

## 5. Security Strategy & Enforcement

**A. 100% Offline Enforcement:**
- The Tauri `allowlist` configuration will explicitly disable all network IPC APIs (e.g., `http` module is blocked).
- The Rust backend will not use modules that interact with external networks. No auto-updates.
- CSP (Content Security Policy) established in the frontend DOM: `default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:;` — enforcing strict local-only loading.

**B. Access Control & Login:**
- **Startup:** Application queries the `config` table.
- **Uninitialized:** Routes strictly to the Setup Wizard (Business Name, Admin Password, USB preferences).
- **Initialized:** Prompts for Password. Authenticated against the Argon2 hash.
- **Brute-force Protection:** After 3 failed attempts, the application triggers a time-based lock using a securely stored counter and timestamp.

**C. USB Manager Sandbox:**
- Rust backend uses OS-level event listeners to detect USB mount activity.
- Retrieves true device `Serial` and `VolumeID`.
- If an unrecognized USB is inserted, AVGVSTO blocks access.
- Files transferred from/to the USB are handled inside a memory sandbox, undergoing integrity checks (Poly1305 MAC validation) before being written to or decrypted from the secure local vault.
