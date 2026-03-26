# AVGVSTO 4.0 — Advanced Encryption Suite

**AVGVSTO 4.0** is an impenetrable, hardware-bound AES-256-GCM encryption suite specifically tailored for business environments and high-security needs. By tying cryptographic keys directly to the physical fingerprint of a USB drive and enforcing robust anti-bruteforce mechanics, mathematical security is unified with physical custody. 

Without the exact, physically registered USB drive inserted into the computer, decryption is mathematically impossible—even if the master password is provided.

## Core Features

- **USB Hardware Fingerprinting:** Combines the Master Password with the unique `Serial` and `VolumeID` of the registered USB stick via PBKDF2 (1 million iterations).
- **Offline Immutability:** 100% offline. Zero network calls, no telemetry, no CDNs.
- **AES-256-GCM & ChaCha20 Support:** Highly secure, authenticated encryption masking data under IND-CCA2 security models. "Business" tier supports a double-layered protocol (Cascade Encryption: AES-256-GCM → ChaCha20-Poly1305).
- **Anti-Bruteforce Engine:** Implements persistent attempt tracking inside `~/.avgvsto/attempts/`. After 3 failed hits, the decryption slot is hard-locked.
- **Secure Delete Engine:** Operates a best-effort 3-pass overwrite before file unlinking.
- **Auditable Tamper-Proof Logging:** Fully signed operations history (`audit.log`) utilizing cryptographic HMACs per entry. Built for IT compliance laws.
- **Silent Deployment:** Allows network administrators to push automated, setup-less configurations to all terminals using an `avgvsto_deploy.json` file.
- **Local Vault Backup:** Integrated local offline backup system allowing IT to archive and snapshot encrypted instances securely.

## System Requirements

- Python 3.8+
- Read/Write privileges for `~/.avgvsto` (or portable flag directory).

## Installation

1. Clone or download the repository.
2. Install the necessary Python packages:

```bash
pip install -r requirements.txt
```

*(Note: dependencies include `pycryptodome` for the cryptographic core and `psutil` for cross-platform hardware detection. GUI usage requires `tkinterdnd2`, `Pillow`, and `pystray`)*

## Portable Mode (Air-Gapped Systems)

If you place a blank file named `.avgvsto_portable` next to the `AVGVSTO_BUSINESS_T.py` script, AVGVSTO routes all internal config tracking (including attempt states and logs) away from `~/.avgvsto` to an adjacent `.avgvsto_config/` directory.

Ideal for moving the entire application strictly on the authorized USB itself. 

## CLI Usage

### Encrypt Data
Encrypt files or directories, and bind them to the inserted USB:
```bash
python AVGVSTO_BUSINESS_T.py encrypt <file_or_folder> [--usb PATH] [--attempts N]
```

### Decrypt Data
Unlock `.avgvsto` secure archives (Requires the correct USB inserted):
```bash
python AVGVSTO_BUSINESS_T.py decrypt <file_or_folder> [--usb PATH]
```

### Bind a USB 
Register a drive with the system to serve as your physical hardware key:
```bash
python AVGVSTO_BUSINESS_T.py bind-usb <path>
```

### Verify Integrity
Check an `.avgvsto` archive's metadata tags without decryption:
```bash
python AVGVSTO_BUSINESS_T.py verify <file>
```

### View Audits & Status
Check usage logs and backend attempt state:
```bash
python AVGVSTO_BUSINESS_T.py status
```

## Security Disclaimer
The algorithms used here are strong and industry-standard. However, **losing your USB token means permanently losing your files**. Do not forget to setup the hidden USB Reset Password or utilize the internal Secure Local Backup feature to protect against hardware failure. 

## License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.

You are free to use it for personal, research, or charitable purposes. Commercial usage, sublicensing, or integration into a sold product is strictly prohibited under this license. See the `LICENSE` file for details.
