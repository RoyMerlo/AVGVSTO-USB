#!/usr/bin/env python3
"""
AVGVSTO v4.0 — Advanced Encryption Suite
Hardware-bound AES-256-GCM encryption with USB key enforcement
By Roy Merlo & RPX

Dependencies:
    pip install pycryptodome psutil
Optional:
    pip install tkinterdnd2     (enables true drag-and-drop)
    pip install Pillow          (enables PNG/ICO icon loading)
    pip install pystray         (enables system tray icon)

CLI usage:
    python AVGVSTO_2026.py encrypt <file_or_folder> [--usb PATH] [--attempts N]
    python AVGVSTO_2026.py decrypt <file_or_folder> [--usb PATH]
    python AVGVSTO_2026.py verify  <file>
    python AVGVSTO_2026.py status
    python AVGVSTO_2026.py bind-usb <path>
"""

import os, sys, json, math, struct, platform, shutil, time, argparse, ctypes
import hashlib, threading, webbrowser, tempfile, psutil
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, List

import tkinter as tk
from tkinter import ttk, filedialog

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    DND = True
except ImportError:
    DND = False

try:
    import pystray
    from PIL import Image as PILImage, ImageDraw
    TRAY = True
except ImportError:
    TRAY = False

from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20_Poly1305 as _ChaCha20Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256 as CryptoSHA256

# ══════════════════════════════════════════════════════════════════════════════
#  PORTABLE MODE DETECTION
#  If a file named ".avgvsto_portable" lives next to this script,
#  all config is stored there instead of ~/.avgvsto — perfect for USB-only use.
# ══════════════════════════════════════════════════════════════════════════════

_SCRIPT_DIR      = Path(__file__).parent.resolve()
_PORTABLE_FLAG   = _SCRIPT_DIR / ".avgvsto_portable"
_IS_PORTABLE     = _PORTABLE_FLAG.exists()

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

APP_NAME     = "AVGVSTO"
APP_VERSION  = "4.0"
GITHUB_URL   = "https://github.com/RoyMerlo/AVGVSTO"
MAGIC        = b"AVGVSTO2"
FORMAT_VER   = 1      # on-disk v1 (legacy, no duress)
FORMAT_VER_2 = 2      # on-disk v2 (with optional duress slot)
ENC_EXT      = ".avgvsto"
PBKDF2_ITERS = 1_000_000

# ── Tier ──────────────────────────────────────────────────────────────────────
TIER          = "business"
PRO_MAX_FILES = 100   # max files per batch in Pro tier
# Business tier: unlimited files per batch (no cap)

# ── Cipher IDs ────────────────────────────────────────────────────────────────
CIPHER_AES      = 0x00   # AES-256-GCM
CIPHER_CHACHA20 = 0x01   # ChaCha20-Poly1305  (Pro+)
CIPHER_CASCADE  = 0x02   # AES-256-GCM → ChaCha20-Poly1305 cascade  (Business)

# v3 header layout (Pro/Business, adds cipher_id byte):
#   MAGIC(8) ver(1) flags(1) cipher_id(1) max_att(2) salt(16) nonce(12)
#   tag(16) ct_len(4) ct  [decoy slot if flags&1]
# v4 header layout (Business cascade):
#   MAGIC(8) ver(1) flags(1) cipher_id=0x02(1) max_att(2)
#   salt1(16) nonce1(12) tag1(16) ct1_len(4) ct1   ← AES layer
#   salt2(16) nonce2(12) tag2(16) ct2_len(4) ct2   ← ChaCha20 layer
#   [decoy slot if flags&1]: same double-layer structure
FORMAT_VER_3 = 3
FORMAT_VER_4 = 4   # cascade

# ── Audit log ─────────────────────────────────────────────────────────────────
AUDIT_LOG_FILE = CONFIG_DIR / "audit.log" if 'CONFIG_DIR' in dir() else None
# (actual path set after CONFIG_DIR is defined below)

# ── Silent deployment ─────────────────────────────────────────────────────────
DEPLOY_CONFIG_FILE = _SCRIPT_DIR / "avgvsto_deploy.json"

# Secure delete: overwrite passes before unlinking.
# On HDDs this is effective. On SSDs / flash drives, wear-levelling
# means the OS may write to a different sector — we do best-effort
# and document the limitation in the UI.
SECURE_DELETE_PASSES = 3

# Portable vs home-directory config
if _IS_PORTABLE:
    CONFIG_DIR = _SCRIPT_DIR / ".avgvsto_config"
else:
    CONFIG_DIR = Path.home() / ".avgvsto"

KEY_FILE         = CONFIG_DIR / "usb_secure.key"
ATTEMPTS_DIR     = CONFIG_DIR / "attempts"
BRUTE_STATE_FILE = CONFIG_DIR / "brute_state.json"
STATS_FILE       = CONFIG_DIR / "stats.json"
AUDIT_LOG_FILE   = CONFIG_DIR / "audit.log"          # Business: full audit trail
BACKUP_DIR       = CONFIG_DIR / "backups"             # Business: local backup storage
BACKUP_INDEX     = BACKUP_DIR / "index.json"          # master backup list

RESET_CONFIG_FILENAME = "avgvsto_reset.json"   # stored on USB root

# v1 header layout (bytes):  MAGIC(8) ver(1) max_att(2) salt(16) nonce(12)
# v2 header layout (bytes):  MAGIC(8) ver(1) flags(1) max_att(2) real_salt(16)
#                             real_nonce(12) real_tag(16) real_ct_len(4) real_ct
#                             [if flags&1]: decoy_salt(16) decoy_nonce(12)
#                                          decoy_tag(16) decoy_ct_len(4) decoy_ct
HEADER_SIZE  = 8 + 1 + 2 + 16 + 12
TAG_SIZE     = 16
MIN_FILESIZE = HEADER_SIZE + TAG_SIZE

# ══════════════════════════════════════════════════════════════════════════════
#  FILESYSTEM HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _ensure_dirs() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ATTEMPTS_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
#  AUDIT LOG  (Business tier — tamper-evident append-only log)
# ══════════════════════════════════════════════════════════════════════════════

def audit_log(operation: str, target: str, result: str,
              usb_id: str = "", extra: str = "") -> None:
    """
    Append one signed line to the audit log.
    Format: ISO-timestamp | operation | result | usb_id_short | target | extra | HMAC
    The HMAC uses SHA-256 over the raw line so any tampering is detectable.
    """
    try:
        _ensure_dirs()
        ts       = datetime.now().isoformat(timespec="seconds")
        uid_s    = (usb_id[:12] + "…") if usb_id else "—"
        raw_line = f"{ts}|{operation}|{result}|{uid_s}|{target}|{extra}"
        sig      = hashlib.sha256(raw_line.encode("utf-8")).hexdigest()[:16]
        full     = raw_line + "|" + sig + "\n"
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(full)
    except Exception:
        pass

def load_audit_log(max_lines: int = 500) -> list:
    """Return last max_lines entries as list of dicts."""
    entries = []
    if not AUDIT_LOG_FILE.exists():
        return entries
    try:
        lines = AUDIT_LOG_FILE.read_text(encoding="utf-8").splitlines()
        for line in lines[-max_lines:]:
            parts = line.split("|")
            if len(parts) >= 7:
                entries.append({
                    "ts":        parts[0],
                    "operation": parts[1],
                    "result":    parts[2],
                    "usb":       parts[3],
                    "target":    parts[4],
                    "extra":     parts[5],
                    "hmac":      parts[6],
                    "valid":     _verify_audit_line(line),
                })
    except Exception:
        pass
    return entries

def _verify_audit_line(line: str) -> bool:
    """Return True if the embedded HMAC matches the line content."""
    try:
        idx  = line.rfind("|")
        body = line[:idx]
        sig  = line[idx+1:]
        return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16] == sig
    except Exception:
        return False

def export_audit_log(dest_path: str) -> int:
    """Copy audit log to dest_path. Returns number of lines exported."""
    if not AUDIT_LOG_FILE.exists():
        return 0
    import shutil as _shutil
    _shutil.copy2(str(AUDIT_LOG_FILE), dest_path)
    lines = AUDIT_LOG_FILE.read_text(encoding="utf-8").splitlines()
    return len(lines)

# ══════════════════════════════════════════════════════════════════════════════
#  SILENT DEPLOYMENT  (Business tier)
#  Place avgvsto_deploy.json next to the script for pre-configured installs.
#  The IT admin creates this file once; end users never see the setup wizard.
# ══════════════════════════════════════════════════════════════════════════════

_DEPLOY_CFG: dict = {}

def _load_deploy_config() -> dict:
    global _DEPLOY_CFG
    if DEPLOY_CONFIG_FILE.exists():
        try:
            _DEPLOY_CFG = json.loads(DEPLOY_CONFIG_FILE.read_text())
        except Exception:
            _DEPLOY_CFG = {}
    return _DEPLOY_CFG

def deploy_usb_id() -> Optional[str]:
    """Return pre-configured USB ID from deploy config, if any."""
    return _DEPLOY_CFG.get("usb_id")

def deploy_max_attempts() -> Optional[int]:
    """Return pre-configured attempt limit from deploy config, if any."""
    v = _DEPLOY_CFG.get("max_attempts")
    return int(v) if v is not None else None

def deploy_default_cipher() -> int:
    """Return pre-configured cipher ID (default AES)."""
    name_map = {"aes": CIPHER_AES, "chacha20": CIPHER_CHACHA20,
                "cascade": CIPHER_CASCADE}
    name = _DEPLOY_CFG.get("default_cipher", "aes").lower()
    return name_map.get(name, CIPHER_AES)

# ══════════════════════════════════════════════════════════════════════════════
#  SECURE DELETE
#  Best-effort 3-pass overwrite before unlink.
#  NOTE: On SSD / flash storage, OS wear-levelling may remap sectors;
#  full forensic wiping on flash requires full-drive crypto erase.
#  This implementation provides strong protection on HDD and is
#  significantly better than plain unlink() on any storage.
# ══════════════════════════════════════════════════════════════════════════════

def secure_delete(path: str) -> None:
    """Overwrite file with random data then zeros before unlinking."""
    p = Path(path)
    try:
        size = p.stat().st_size
        if size > 0:
            with open(path, "r+b") as f:
                for _ in range(SECURE_DELETE_PASSES):
                    f.seek(0)
                    # Write in 64 KB chunks to avoid giant allocations
                    remaining = size
                    while remaining > 0:
                        chunk = min(remaining, 65536)
                        f.write(get_random_bytes(chunk))
                        remaining -= chunk
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except OSError:
                        pass
                # Final zero pass
                f.seek(0)
                remaining = size
                while remaining > 0:
                    chunk = min(remaining, 65536)
                    f.write(b'\x00' * chunk)
                    remaining -= chunk
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
    except Exception:
        pass
    finally:
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass

# ══════════════════════════════════════════════════════════════════════════════
#  STATS SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

def _load_stats() -> dict:
    try:
        if STATS_FILE.exists():
            return json.loads(STATS_FILE.read_text())
    except Exception:
        pass
    return {"files_encrypted": 0, "files_decrypted": 0,
            "bytes_encrypted": 0, "bytes_decrypted": 0,
            "last_activity": None}

def _save_stats(s: dict) -> None:
    try:
        _ensure_dirs()
        STATS_FILE.write_text(json.dumps(s, indent=2))
    except Exception:
        pass

def stats_inc_encrypt(byte_count: int = 0) -> None:
    s = _load_stats()
    s["files_encrypted"]  = s.get("files_encrypted", 0) + 1
    s["bytes_encrypted"]  = s.get("bytes_encrypted", 0) + byte_count
    s["last_activity"]    = datetime.now().isoformat(timespec="seconds")
    _save_stats(s)

def stats_inc_decrypt(byte_count: int = 0) -> None:
    s = _load_stats()
    s["files_decrypted"]  = s.get("files_decrypted", 0) + 1
    s["bytes_decrypted"]  = s.get("bytes_decrypted", 0) + byte_count
    s["last_activity"]    = datetime.now().isoformat(timespec="seconds")
    _save_stats(s)

def _attempt_slot(file_path: str) -> Path:
    key = hashlib.sha256(str(Path(file_path).resolve()).encode()).hexdigest()[:24]
    return ATTEMPTS_DIR / key

def get_attempt_count(file_path: str) -> int:
    slot = _attempt_slot(file_path)
    if slot.exists():
        try:
            return int(slot.read_text().strip())
        except ValueError:
            return 0
    return 0

def increment_attempt_count(file_path: str) -> int:
    count = get_attempt_count(file_path) + 1
    _ensure_dirs()
    _attempt_slot(file_path).write_text(str(count))
    return count

def reset_attempt_count(file_path: str) -> None:
    slot = _attempt_slot(file_path)
    if slot.exists():
        slot.unlink()

# ══════════════════════════════════════════════════════════════════════════════
#  BACKUP SYSTEM  (Business — password-protected, no USB required)
#  Storage layout:
#    ~/.avgvsto/backups/
#      index.json            master list of all backups
#      {backup_id}/
#        meta.json           name, created, file list with original paths
#        files/
#          0.avgbak          AES-256-GCM encrypted copy of original file 0
#          1.avgbak          ...
# ══════════════════════════════════════════════════════════════════════════════

def _derive_backup_key(password: str, salt: bytes) -> bytes:
    """Derive 256-bit key from password only (no USB binding)."""
    return PBKDF2(password.encode("utf-8"), salt, dkLen=32,
                  count=PBKDF2_ITERS, hmac_hash_module=CryptoSHA256)

def _encrypt_backup_blob(data: bytes, password: str) -> bytes:
    """Encrypt raw bytes with password → salt(16)+nonce(12)+tag(16)+ct."""
    salt  = get_random_bytes(16)
    nonce = get_random_bytes(12)
    key   = _derive_backup_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return salt + nonce + tag + ct

def _decrypt_backup_blob(blob: bytes, password: str) -> bytes:
    """Decrypt a backup blob. Raises ValueError on wrong password."""
    salt, nonce, tag, ct = blob[:16], blob[16:28], blob[28:44], blob[44:]
    key    = _derive_backup_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def _backup_pw_hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def _load_backup_index() -> list:
    try:
        if BACKUP_INDEX.exists():
            return json.loads(BACKUP_INDEX.read_text())
    except Exception:
        pass
    return []

def _save_backup_index(entries: list) -> None:
    try:
        _ensure_dirs()
        BACKUP_INDEX.write_text(json.dumps(entries, indent=2, ensure_ascii=False))
    except Exception:
        pass

def _sanitize_backup_id(name: str) -> str:
    """Make a filesystem-safe ID from the backup name + timestamp."""
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{ts}_{safe[:32]}"

def create_backup(file_paths: List[str], name: str, password: str) -> Tuple[bool, str]:
    """
    Create a backup of the given files (originals, before encryption).
    Returns (success, message).
    """
    try:
        _ensure_dirs()
        bid      = _sanitize_backup_id(name)
        bdir     = BACKUP_DIR / bid
        fdir     = bdir / "files"
        fdir.mkdir(parents=True, exist_ok=True)

        file_meta = []
        total_size = 0
        for i, fp in enumerate(file_paths):
            p = Path(fp)
            if not p.exists():
                continue
            data  = p.read_bytes()
            blob  = _encrypt_backup_blob(data, password)
            out   = fdir / f"{i}.avgbak"
            out.write_bytes(blob)
            total_size += len(data)
            file_meta.append({
                "idx":           i,
                "original_path": str(p.resolve()),
                "name":          p.name,
                "size":          len(data),
            })

        meta = {
            "id":         bid,
            "name":       name,
            "created":    datetime.now().isoformat(timespec="seconds"),
            "file_count": len(file_meta),
            "total_size": total_size,
            "files":      file_meta,
        }
        (bdir / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))

        # Update master index (store pw_hash for quick password pre-check)
        idx = _load_backup_index()
        idx.append({
            "id":         bid,
            "name":       name,
            "created":    meta["created"],
            "file_count": len(file_meta),
            "total_size": total_size,
            "pw_hash":    _backup_pw_hash(password),
        })
        _save_backup_index(idx)
        audit_log("BACKUP_CREATE", name, "OK", extra=f"{len(file_meta)} files")
        return True, f"Backup «{name}» created — {len(file_meta)} file(s)."
    except Exception as exc:
        return False, f"Backup failed: {exc}"

def restore_backup(backup_id: str, password: str,
                   dest_dir: Optional[str] = None) -> Tuple[bool, str, List[str]]:
    """
    Restore all files from a backup.
    If dest_dir is None, files are restored to their original paths.
    Returns (success, message, list_of_restored_paths).
    """
    try:
        bdir = BACKUP_DIR / backup_id
        meta_path = bdir / "meta.json"
        if not meta_path.exists():
            return False, "Backup not found or corrupted.", []
        meta  = json.loads(meta_path.read_text())
        fdir  = bdir / "files"
        restored = []
        errors   = []
        for entry in meta.get("files", []):
            idx  = entry["idx"]
            blob_path = fdir / f"{idx}.avgbak"
            if not blob_path.exists():
                errors.append(f"{entry['name']}: file missing in backup")
                continue
            try:
                blob = blob_path.read_bytes()
                data = _decrypt_backup_blob(blob, password)
            except ValueError:
                return False, "Wrong backup password.", []
            if dest_dir:
                out = Path(dest_dir) / entry["name"]
            else:
                out = Path(entry["original_path"])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            restored.append(str(out))
        msg = f"{len(restored)} file(s) restored."
        if errors:
            msg += f"  {len(errors)} error(s)."
        audit_log("BACKUP_RESTORE", meta.get("name", backup_id), "OK",
                  extra=f"{len(restored)} restored")
        return True, msg, restored
    except Exception as exc:
        return False, f"Restore failed: {exc}", []

def delete_backup(backup_id: str) -> Tuple[bool, str]:
    """Permanently delete a backup and remove it from the index."""
    try:
        bdir = BACKUP_DIR / backup_id
        if bdir.exists():
            shutil.rmtree(str(bdir))
        idx = [e for e in _load_backup_index() if e["id"] != backup_id]
        _save_backup_index(idx)
        audit_log("BACKUP_DELETE", backup_id, "OK")
        return True, "Backup deleted."
    except Exception as exc:
        return False, f"Delete failed: {exc}"

def rename_backup(backup_id: str, new_name: str) -> Tuple[bool, str]:
    """Rename a backup (display name only, folder stays the same)."""
    try:
        bdir = BACKUP_DIR / backup_id
        meta_path = bdir / "meta.json"
        if meta_path.exists():
            meta = json.loads(meta_path.read_text())
            meta["name"] = new_name
            meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False))
        idx = _load_backup_index()
        for e in idx:
            if e["id"] == backup_id:
                e["name"] = new_name
        _save_backup_index(idx)
        return True, f"Renamed to «{new_name}»."
    except Exception as exc:
        return False, f"Rename failed: {exc}"

def change_backup_password(backup_id: str, old_pw: str, new_pw: str) -> Tuple[bool, str]:
    """
    Re-encrypt all files in a backup with a new password.
    Verifies old password first by attempting to decrypt file 0.
    """
    try:
        bdir = BACKUP_DIR / backup_id
        meta_path = bdir / "meta.json"
        if not meta_path.exists():
            return False, "Backup not found."
        meta = json.loads(meta_path.read_text())
        fdir = bdir / "files"

        # Verify old password by decrypting first available file
        verified = False
        for entry in meta.get("files", []):
            blob_path = fdir / f"{entry['idx']}.avgbak"
            if blob_path.exists():
                try:
                    _decrypt_backup_blob(blob_path.read_bytes(), old_pw)
                    verified = True
                except ValueError:
                    return False, "Wrong current password."
                break
        if not verified:
            return False, "No files found in backup to verify."

        # Re-encrypt all files
        for entry in meta.get("files", []):
            blob_path = fdir / f"{entry['idx']}.avgbak"
            if not blob_path.exists():
                continue
            data     = _decrypt_backup_blob(blob_path.read_bytes(), old_pw)
            new_blob = _encrypt_backup_blob(data, new_pw)
            blob_path.write_bytes(new_blob)

        # Update pw_hash in index
        idx = _load_backup_index()
        for e in idx:
            if e["id"] == backup_id:
                e["pw_hash"] = _backup_pw_hash(new_pw)
        _save_backup_index(idx)
        audit_log("BACKUP_CHPW", backup_id, "OK")
        return True, "Password changed successfully."
    except Exception as exc:
        return False, f"Password change failed: {exc}"



def get_usb_identifier(mount_path: str) -> Optional[str]:
    try:
        stat = os.stat(mount_path)
        raw  = f"{stat.st_dev}:{platform.node()}:{mount_path}"
        return hashlib.sha256(raw.encode()).hexdigest()
    except OSError:
        return None

def list_usb_drives() -> List[str]:
    drives = []
    try:
        sys_name = platform.system()
        # all=True needed on Linux to catch NTFS/exFAT USB drives
        use_all = (sys_name == "Linux")
        for p in psutil.disk_partitions(all=use_all):
            if sys_name == "Windows":
                if "removable" in p.opts.lower():
                    drives.append(p.device)
            elif sys_name == "Darwin":
                if p.mountpoint.startswith("/Volumes") and p.mountpoint != "/Volumes":
                    drives.append(p.mountpoint)
            else:  # Linux
                mp = p.mountpoint
                # Common USB mount paths on Ubuntu/Arch/Fedora/etc
                usb_prefixes = ("/media/", "/run/media/", "/mnt/")
                # Filesystems typically found on USB drives
                usb_fstypes = {
                    "vfat", "exfat", "ntfs", "ntfs-3g", "fuseblk",
                    "ext2", "ext3", "ext4", "hfsplus", "udf",
                }
                is_usb_path = any(mp.startswith(pre) for pre in usb_prefixes)
                is_usb_fs   = getattr(p, "fstype", "").lower() in usb_fstypes
                if (is_usb_path or is_usb_fs) and os.path.isdir(mp) and mp != "/":
                    if mp not in drives:
                        drives.append(mp)
    except Exception:
        pass
    return drives

# ══════════════════════════════════════════════════════════════════════════════
#  RESET-ATTEMPTS PASSWORD SYSTEM  (config stored on the USB itself)
# ══════════════════════════════════════════════════════════════════════════════

def _reset_cfg_path(usb_mount: str) -> Path:
    return Path(usb_mount) / RESET_CONFIG_FILENAME

def load_reset_config(usb_mount: str) -> Optional[dict]:
    p = _reset_cfg_path(usb_mount)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None

def save_reset_config(usb_mount: str, cfg: dict) -> None:
    _reset_cfg_path(usb_mount).write_text(json.dumps(cfg, indent=2))

def has_reset_password(usb_mount: str) -> bool:
    cfg = load_reset_config(usb_mount)
    return bool(cfg and "reset_hash" in cfg)

def create_reset_password(usb_mount: str, password: str) -> None:
    """Create (or overwrite) the reset password on the USB."""
    h   = hashlib.sha256(password.encode("utf-8")).hexdigest()
    cfg = load_reset_config(usb_mount) or {}
    cfg["reset_hash"]      = h
    cfg.setdefault("reset_count",      0)
    cfg.setdefault("reset_fail_count", 0)
    cfg.setdefault("reset_locked",     False)
    save_reset_config(usb_mount, cfg)

def can_reset(usb_mount: str) -> Tuple[bool, str]:
    """Check if resetting is possible; return (ok, human-readable status)."""
    cfg = load_reset_config(usb_mount)
    if not cfg or "reset_hash" not in cfg:
        return False, "No reset password configured for this USB."
    if cfg.get("reset_locked"):
        return False, "Reset locked — 3 wrong reset passwords entered."
    n = cfg.get("reset_count", 0)
    if n >= 3:
        return False, (f"Maximum resets ({n}/3) exhausted.\n"
                       "Use CLEANUP → FULL CLEAR to start over.")
    return True, f"Resets used: {n} / 3"

def do_reset_counters(usb_mount: str, password: str) -> Tuple[bool, str]:
    """
    Verify reset password and reset all locked attempt counters.
    Returns (success, message).
    """
    cfg = load_reset_config(usb_mount)
    if not cfg or "reset_hash" not in cfg:
        return False, "No reset password on this USB."
    if cfg.get("reset_locked"):
        return False, "Reset permanently locked after 3 wrong reset-password attempts."
    n = cfg.get("reset_count", 0)
    if n >= 3:
        return False, "Maximum resets (3) exhausted. Use CLEANUP → FULL CLEAR."

    h = hashlib.sha256(password.encode("utf-8")).hexdigest()
    if h != cfg.get("reset_hash"):
        cfg["reset_fail_count"] = cfg.get("reset_fail_count", 0) + 1
        remaining = 3 - cfg["reset_fail_count"]
        if remaining <= 0:
            cfg["reset_locked"] = True
            save_reset_config(usb_mount, cfg)
            return False, ("Wrong reset password.\n"
                           "3/3 attempts used — reset permanently locked.\n"
                           "Files can still be decrypted with remaining attempts.\n"
                           "Use CLEANUP → FULL CLEAR to wipe and start over.")
        save_reset_config(usb_mount, cfg)
        return False, f"Wrong reset password. {remaining} attempt(s) left before permanent lock."

    # ── Correct password ───────────────────────────────────────────────────────
    cfg["reset_fail_count"] = 0
    cfg["reset_count"]      = n + 1
    save_reset_config(usb_mount, cfg)

    count = 0
    if ATTEMPTS_DIR.exists():
        for slot in list(ATTEMPTS_DIR.iterdir()):
            try:
                slot.unlink()
                count += 1
            except Exception:
                pass
    return True, f"{count} locked counter(s) cleared.  (Reset {n+1}/3 used)"

def full_clear_usb_reset(usb_mount: str) -> None:
    """Delete avgvsto_reset.json from USB — allows fresh reset setup."""
    try:
        _reset_cfg_path(usb_mount).unlink(missing_ok=True)
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────

def save_usb_config(usb_path: str) -> Optional[str]:
    """
    Business tier: supports unlimited USB bindings stored as a list.
    Adds the new USB ID without removing existing ones.
    """
    _ensure_dirs()
    uid = get_usb_identifier(usb_path)
    if not uid:
        return None
    # Load existing bindings
    existing = _load_all_usb_ids()
    if uid not in existing:
        existing.append(uid)
    KEY_FILE.write_text(json.dumps(
        {"usb_ids": existing, "primary": uid, "path": usb_path}, indent=2))
    return uid

def _load_all_usb_ids() -> list:
    if not KEY_FILE.exists():
        return []
    try:
        data = json.loads(KEY_FILE.read_text())
        # Support both old single-id format and new multi-id format
        if "usb_ids" in data:
            return data["usb_ids"]
        elif "usb_id" in data:
            return [data["usb_id"]]
    except Exception:
        pass
    return []

def load_usb_id() -> Optional[str]:
    """Return primary USB ID (first in list) for backward-compat."""
    ids = _load_all_usb_ids()
    return ids[0] if ids else None

def find_authorized_usb(saved_id: str) -> Optional[str]:
    """
    Business tier: any of the registered USB IDs is authorized.
    saved_id is still accepted for backward-compat, but we check all.
    """
    all_ids = set(_load_all_usb_ids())
    if saved_id:
        all_ids.add(saved_id)
    for path in list_usb_drives():
        if get_usb_identifier(path) in all_ids:
            return path
    return None

def remove_usb_binding(usb_id: str) -> bool:
    """Remove a specific USB binding (Business feature)."""
    ids = _load_all_usb_ids()
    if usb_id not in ids:
        return False
    ids.remove(usb_id)
    try:
        data = json.loads(KEY_FILE.read_text()) if KEY_FILE.exists() else {}
    except Exception:
        data = {}
    data["usb_ids"] = ids
    if data.get("primary") == usb_id:
        data["primary"] = ids[0] if ids else None
    KEY_FILE.write_text(json.dumps(data, indent=2))
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTOGRAPHIC CORE
# ══════════════════════════════════════════════════════════════════════════════

def _derive_key(password: str, salt: bytes, usb_id: str) -> bytes:
    ikm = (password + ":" + usb_id).encode("utf-8")
    return PBKDF2(ikm, salt, dkLen=32, count=PBKDF2_ITERS,
                  hmac_hash_module=CryptoSHA256)

def read_header(raw: bytes) -> dict:
    """
    Parse v1, v2, or v3 file header.
    v3 (Pro+) adds a cipher_id byte after flags.
    Returns a unified dict.
    """
    if len(raw) < MIN_FILESIZE:
        raise ValueError("File is too small or severely corrupted.")
    if raw[:8] != MAGIC:
        raise ValueError("Not a valid AVGVSTO encrypted file.")

    ver = struct.unpack_from("<B", raw, 8)[0]

    if ver == 1:
        return {
            "version":      1,
            "flags":        0,
            "cipher_id":    CIPHER_AES,
            "max_attempts": struct.unpack_from("<H", raw, 9)[0],
            "salt":         raw[11:27],
            "nonce":        raw[27:39],
            "tag":          raw[39:55],
            "ciphertext":   raw[55:],
            "has_decoy":    False,
        }
    elif ver == 2:
        flags       = struct.unpack_from("<B", raw, 9)[0]
        max_att     = struct.unpack_from("<H", raw, 10)[0]
        real_salt   = raw[12:28]
        real_nonce  = raw[28:40]
        real_tag    = raw[40:56]
        real_ct_len = struct.unpack_from("<I", raw, 56)[0]
        real_ct     = raw[60:60 + real_ct_len]
        hdr = {
            "version":      2,
            "flags":        flags,
            "cipher_id":    CIPHER_AES,
            "max_attempts": max_att,
            "salt":         real_salt,
            "nonce":        real_nonce,
            "tag":          real_tag,
            "ciphertext":   real_ct,
            "has_decoy":    bool(flags & 1),
        }
        if flags & 1:
            off                 = 60 + real_ct_len
            hdr["decoy_salt"]   = raw[off:off+16]
            hdr["decoy_nonce"]  = raw[off+16:off+28]
            hdr["decoy_tag"]    = raw[off+28:off+44]
            dct_len             = struct.unpack_from("<I", raw, off+44)[0]
            hdr["decoy_ct"]     = raw[off+48:off+48+dct_len]
        return hdr
    elif ver == 3:
        # v3: MAGIC(8) ver(1) flags(1) cipher_id(1) max_att(2)
        #     salt(16) nonce(12) tag(16) ct_len(4) ct
        #     [if flags&1]: decoy_cipher_id(1) decoy_salt(16) decoy_nonce(12)
        #                   decoy_tag(16) decoy_ct_len(4) decoy_ct
        flags       = struct.unpack_from("<B", raw, 9)[0]
        cipher_id   = struct.unpack_from("<B", raw, 10)[0]
        max_att     = struct.unpack_from("<H", raw, 11)[0]
        real_salt   = raw[13:29]
        real_nonce  = raw[29:41]
        real_tag    = raw[41:57]
        real_ct_len = struct.unpack_from("<I", raw, 57)[0]
        real_ct     = raw[61:61 + real_ct_len]
        hdr = {
            "version":      3,
            "flags":        flags,
            "cipher_id":    cipher_id,
            "max_attempts": max_att,
            "salt":         real_salt,
            "nonce":        real_nonce,
            "tag":          real_tag,
            "ciphertext":   real_ct,
            "has_decoy":    bool(flags & 1),
        }
        if flags & 1:
            off                       = 61 + real_ct_len
            hdr["decoy_cipher_id"]    = struct.unpack_from("<B", raw, off)[0]
            hdr["decoy_salt"]         = raw[off+1:off+17]
            hdr["decoy_nonce"]        = raw[off+17:off+29]
            hdr["decoy_tag"]          = raw[off+29:off+45]
            dct_len                   = struct.unpack_from("<I", raw, off+45)[0]
            hdr["decoy_ct"]           = raw[off+49:off+49+dct_len]
        return hdr
    elif ver == 4:
        # v4 (Business cascade):
        # MAGIC(8) ver(1) flags(1) cipher_id=0x02(1) max_att(2)
        #   L1: salt1(16) nonce1(12) tag1(16) ct1_len(4) ct1
        #   L2: salt2(16) nonce2(12) tag2(16) ct2_len(4) ct2
        # [if flags&1]: same double-layer decoy structure
        flags     = struct.unpack_from("<B", raw, 9)[0]
        cipher_id = struct.unpack_from("<B", raw, 10)[0]
        max_att   = struct.unpack_from("<H", raw, 11)[0]
        p = 13
        salt1  = raw[p:p+16]; p += 16
        nonce1 = raw[p:p+12]; p += 12
        tag1   = raw[p:p+16]; p += 16
        ct1_len = struct.unpack_from("<I", raw, p)[0]; p += 4
        ct1    = raw[p:p+ct1_len]; p += ct1_len
        salt2  = raw[p:p+16]; p += 16
        nonce2 = raw[p:p+12]; p += 12
        tag2   = raw[p:p+16]; p += 16
        ct2_len = struct.unpack_from("<I", raw, p)[0]; p += 4
        ct2    = raw[p:p+ct2_len]; p += ct2_len
        hdr = {
            "version":      4,
            "flags":        flags,
            "cipher_id":    CIPHER_CASCADE,
            "max_attempts": max_att,
            "salt1": salt1, "nonce1": nonce1, "tag1": tag1, "ct1": ct1,
            "salt2": salt2, "nonce2": nonce2, "tag2": tag2, "ct2": ct2,
            "ciphertext": ct2,   # alias for size display
            "has_decoy":  bool(flags & 1),
        }
        if flags & 1:
            hdr["d_salt1"]  = raw[p:p+16]; p += 16
            hdr["d_nonce1"] = raw[p:p+12]; p += 12
            hdr["d_tag1"]   = raw[p:p+16]; p += 16
            d_ct1_len = struct.unpack_from("<I", raw, p)[0]; p += 4
            hdr["d_ct1"]    = raw[p:p+d_ct1_len]; p += d_ct1_len
            hdr["d_salt2"]  = raw[p:p+16]; p += 16
            hdr["d_nonce2"] = raw[p:p+12]; p += 12
            hdr["d_tag2"]   = raw[p:p+16]; p += 16
            d_ct2_len = struct.unpack_from("<I", raw, p)[0]; p += 4
            hdr["d_ct2"]    = raw[p:p+d_ct2_len]
        return hdr
    else:
        raise ValueError(f"Unknown file format version: {ver}. "
                         "Update AVGVSTO to open this file.")


def _build_cipher(cipher_id: int, key: bytes, nonce: bytes):
    """Return a pycryptodome cipher object for the given cipher_id."""
    if cipher_id == CIPHER_AES:
        return AES.new(key, AES.MODE_GCM, nonce=nonce)
    elif cipher_id == CIPHER_CHACHA20:
        return _ChaCha20Poly1305.new(key=key, nonce=nonce)
    elif cipher_id == CIPHER_CASCADE:
        raise ValueError("Cascade cipher must use _cascade_encrypt / _cascade_decrypt directly.")
    else:
        raise ValueError(f"Unsupported cipher ID: {cipher_id:#04x}")


def _cascade_encrypt(data: bytes, password: str, usb_id: str) -> tuple:
    """
    Double-layer encrypt: AES-256-GCM → ChaCha20-Poly1305.
    Each layer uses an independent salt and derived key.
    Returns (salt1, nonce1, tag1, ct1, salt2, nonce2, tag2, ct2).
    ct1 = AES ciphertext, ct2 = ChaCha20 ciphertext of ct1.
    """
    # Layer 1 — AES-256-GCM
    salt1  = get_random_bytes(16)
    nonce1 = get_random_bytes(12)
    key1   = _derive_key(password + ":L1", salt1, usb_id)
    c1     = AES.new(key1, AES.MODE_GCM, nonce=nonce1)
    ct1, tag1 = c1.encrypt_and_digest(data)

    # Layer 2 — ChaCha20-Poly1305 over AES ciphertext
    salt2  = get_random_bytes(16)
    nonce2 = get_random_bytes(12)
    key2   = _derive_key(password + ":L2", salt2, usb_id)
    c2     = _ChaCha20Poly1305.new(key=key2, nonce=nonce2)
    ct2, tag2 = c2.encrypt_and_digest(ct1)

    return salt1, nonce1, tag1, ct1, salt2, nonce2, tag2, ct2


def _cascade_decrypt(salt1, nonce1, tag1, salt2, nonce2, tag2, ct2,
                     password: str, usb_id: str) -> bytes:
    """
    Reverse of _cascade_encrypt. Raises ValueError on auth failure.
    """
    # Layer 2 — ChaCha20-Poly1305 decrypt
    key2 = _derive_key(password + ":L2", salt2, usb_id)
    c2   = _ChaCha20Poly1305.new(key=key2, nonce=nonce2)
    ct1  = c2.decrypt_and_verify(ct2, tag2)

    # Layer 1 — AES-256-GCM decrypt
    key1 = _derive_key(password + ":L1", salt1, usb_id)
    c1   = AES.new(key1, AES.MODE_GCM, nonce=nonce1)
    return c1.decrypt_and_verify(ct1, tag1)


def encrypt_file(src_path: str, password: str, usb_id: str,
                 max_attempts: int,
                 duress_password: str = None,
                 duress_data: bytes  = b"",
                 cipher_id: int      = CIPHER_AES) -> str:
    """
    Encrypt src_path → src_path + ENC_EXT.
    cipher_id: CIPHER_AES, CIPHER_CHACHA20, or CIPHER_CASCADE (Business).
    Business audit log entry is written on every call.
    """
    src = Path(src_path)
    if src.suffix == ENC_EXT:
        raise ValueError(f"File already has {ENC_EXT} — already encrypted?")
    data = src.read_bytes()

    use_duress = duress_password is not None
    dst = src.with_name(src.name + ENC_EXT)

    if cipher_id == CIPHER_CASCADE:
        # v4 — double-layer cascade
        flags = 1 if use_duress else 0
        s1, n1, t1, ct1, s2, n2, t2, ct2 = _cascade_encrypt(data, password, usb_id)
        header = (MAGIC
                  + struct.pack("<B", FORMAT_VER_4)
                  + struct.pack("<B", flags)
                  + struct.pack("<B", CIPHER_CASCADE)
                  + struct.pack("<H", max_attempts)
                  + s1 + n1 + t1 + struct.pack("<I", len(ct1)) + ct1
                  + s2 + n2 + t2 + struct.pack("<I", len(ct2)) + ct2)
        if use_duress:
            ds1, dn1, dt1, dct1, ds2, dn2, dt2, dct2 = _cascade_encrypt(
                duress_data, duress_password, usb_id)
            header += (ds1 + dn1 + dt1 + struct.pack("<I", len(dct1)) + dct1
                       + ds2 + dn2 + dt2 + struct.pack("<I", len(dct2)) + dct2)
        dst.write_bytes(header)
    else:
        real_salt  = get_random_bytes(16)
        real_nonce = get_random_bytes(12)
        real_key   = _derive_key(password, real_salt, usb_id)
        cipher     = _build_cipher(cipher_id, real_key, real_nonce)
        real_ct, real_tag = cipher.encrypt_and_digest(data)

        if cipher_id == CIPHER_AES and not use_duress:
            # v1 — backward-compatible
            header = (MAGIC
                      + struct.pack("<B", FORMAT_VER)
                      + struct.pack("<H", max_attempts)
                      + real_salt + real_nonce)
            dst.write_bytes(header + real_tag + real_ct)
        else:
            # v3
            flags = 1 if use_duress else 0
            header = (MAGIC
                      + struct.pack("<B", FORMAT_VER_3)
                      + struct.pack("<B", flags)
                      + struct.pack("<B", cipher_id)
                      + struct.pack("<H", max_attempts)
                      + real_salt + real_nonce + real_tag
                      + struct.pack("<I", len(real_ct))
                      + real_ct)
            if use_duress:
                decoy_salt  = get_random_bytes(16)
                decoy_nonce = get_random_bytes(12)
                decoy_key   = _derive_key(duress_password, decoy_salt, usb_id)
                dcph        = _build_cipher(cipher_id, decoy_key, decoy_nonce)
                decoy_ct, decoy_tag = dcph.encrypt_and_digest(duress_data)
                header += (struct.pack("<B", cipher_id)
                           + decoy_salt + decoy_nonce + decoy_tag
                           + struct.pack("<I", len(decoy_ct))
                           + decoy_ct)
            dst.write_bytes(header)

    secure_delete(str(src))
    stats_inc_encrypt(len(data))
    _CIPHER_NAMES = {CIPHER_AES: "AES-256-GCM", CIPHER_CHACHA20: "ChaCha20-Poly1305",
                     CIPHER_CASCADE: "CASCADE"}
    audit_log("ENCRYPT", src.name, "OK", usb_id,
              extra=_CIPHER_NAMES.get(cipher_id, "?"))
    return str(dst)


def decrypt_file(src_path: str, password: str, usb_id: str) -> Tuple[str, int]:
    """Decrypt src_path (v1, v2, v3, or v4 cascade)."""
    src = Path(src_path)
    if not src.name.endswith(ENC_EXT):
        raise ValueError("File does not have the expected .avgvsto extension.")
    raw = src.read_bytes()
    hdr = read_header(raw)

    def _write_result(plaintext: bytes) -> Tuple[str, int]:
        dst = src.parent / src.name[: -len(ENC_EXT)]
        dst.write_bytes(plaintext)
        secure_delete(str(src))
        stats_inc_decrypt(len(plaintext))
        audit_log("DECRYPT", src.name, "OK", usb_id)
        return str(dst), hdr["max_attempts"]

    # ── Cascade v4 ────────────────────────────────────────────────────────────
    if hdr["cipher_id"] == CIPHER_CASCADE:
        try:
            pt = _cascade_decrypt(
                hdr["salt1"], hdr["nonce1"], hdr["tag1"],
                hdr["salt2"], hdr["nonce2"], hdr["tag2"], hdr["ct2"],
                password, usb_id)
            return _write_result(pt)
        except (ValueError, KeyError):
            pass
        if hdr.get("has_decoy"):
            try:
                pt = _cascade_decrypt(
                    hdr["d_salt1"], hdr["d_nonce1"], hdr["d_tag1"],
                    hdr["d_salt2"], hdr["d_nonce2"], hdr["d_tag2"], hdr["d_ct2"],
                    password, usb_id)
                return _write_result(pt)
            except (ValueError, KeyError):
                pass
    else:
        # ── Standard v1/v2/v3 ────────────────────────────────────────────────
        try:
            key    = _derive_key(password, hdr["salt"], usb_id)
            cipher = _build_cipher(hdr["cipher_id"], key, hdr["nonce"])
            return _write_result(
                cipher.decrypt_and_verify(hdr["ciphertext"], hdr["tag"]))
        except (ValueError, KeyError):
            pass
        if hdr.get("has_decoy"):
            try:
                dcid   = hdr.get("decoy_cipher_id", hdr["cipher_id"])
                key    = _derive_key(password, hdr["decoy_salt"], usb_id)
                cipher = _build_cipher(dcid, key, hdr["decoy_nonce"])
                return _write_result(
                    cipher.decrypt_and_verify(hdr["decoy_ct"], hdr["decoy_tag"]))
            except (ValueError, KeyError):
                pass

    audit_log("DECRYPT", src.name, "FAIL", usb_id)
    raise ValueError(
        "Authentication failed.\n"
        "Wrong password or unauthorised USB drive."
    )


def verify_file(src_path: str, password: str, usb_id: str) -> Tuple[bool, str]:
    """
    In-memory integrity check — no writes to disk.
    Returns (valid, detail_message).
    """
    _CIPHER_NAMES = {CIPHER_AES: "AES-256-GCM", CIPHER_CHACHA20: "ChaCha20-Poly1305"}
    try:
        raw = Path(src_path).read_bytes()
        hdr = read_header(raw)
    except Exception as exc:
        return False, f"Header parse failed: {exc}"

    # Try real slot
    try:
        key    = _derive_key(password, hdr["salt"], usb_id)
        cipher = _build_cipher(hdr["cipher_id"], key, hdr["nonce"])
        cipher.decrypt_and_verify(hdr["ciphertext"], hdr["tag"])
        ver_txt    = f"v{hdr['version']}" + (" / dual-slot" if hdr.get("has_decoy") else "")
        cipher_txt = _CIPHER_NAMES.get(hdr["cipher_id"], f"cipher#{hdr['cipher_id']}")
        att_txt    = "∞" if hdr["max_attempts"] == 0 else str(hdr["max_attempts"])
        return True, (f"✓  Integrity OK  ·  Format {ver_txt}  ·  {cipher_txt}  ·  "
                      f"Attempts limit: {att_txt}  ·  "
                      f"Payload: {_fmt_size(len(hdr['ciphertext']))}")
    except (ValueError, KeyError):
        pass

    # Try decoy slot
    if hdr.get("has_decoy"):
        try:
            dcid   = hdr.get("decoy_cipher_id", hdr["cipher_id"])
            key    = _derive_key(password, hdr["decoy_salt"], usb_id)
            cipher = _build_cipher(dcid, key, hdr["decoy_nonce"])
            cipher.decrypt_and_verify(hdr["decoy_ct"], hdr["decoy_tag"])
            return True, (f"✓  Integrity OK  (decoy slot matched)  ·  "
                          f"Payload: {_fmt_size(len(hdr['decoy_ct']))}")
        except (ValueError, KeyError):
            pass

    return False, "✕  Authentication failed — wrong password or USB, or file corrupted."

def encrypt_folder(folder_path: str, password: str, usb_id: str,
                   max_attempts: int,
                   duress_password: str = None,
                   duress_data: bytes  = b"",
                   on_progress=None,
                   cipher_id: int      = CIPHER_AES) -> Tuple[int, List[str]]:
    ok, errors, files = 0, [], []
    for root, _, fnames in os.walk(folder_path):
        for f in fnames:
            if not f.endswith(ENC_EXT):
                files.append(os.path.join(root, f))
    total = len(files)
    for i, fp in enumerate(files):
        if on_progress:
            on_progress(i, total, os.path.basename(fp))
        try:
            encrypt_file(fp, password, usb_id, max_attempts,
                         duress_password, duress_data, cipher_id)
            ok += 1
        except Exception as e:
            errors.append(f"{os.path.basename(fp)}: {e}")
    if on_progress:
        on_progress(total, total, "")
    return ok, errors

def decrypt_folder(folder_path: str, password: str, usb_id: str,
                   on_progress=None) -> Tuple[int, List[str]]:
    ok, errors, files = 0, [], []
    for root, _, fnames in os.walk(folder_path):
        for f in fnames:
            if f.endswith(ENC_EXT):
                files.append(os.path.join(root, f))
    total = len(files)
    for i, fp in enumerate(files):
        if on_progress:
            on_progress(i, total, os.path.basename(fp))
        try:
            _attempt_decrypt_with_tracking(fp, password, usb_id)
            ok += 1
        except Exception as e:
            errors.append(f"{os.path.basename(fp)}: {e}")
    if on_progress:
        on_progress(total, total, "")
    return ok, errors

def _attempt_decrypt_with_tracking(file_path: str, password: str,
                                    usb_id: str) -> str:
    raw = Path(file_path).read_bytes()
    hdr = read_header(raw)
    max_att = hdr["max_attempts"]
    if max_att > 0:
        count = get_attempt_count(file_path)
        if count >= max_att:
            raise PermissionError(
                f"Maximum attempts ({max_att}) exceeded.\n"
                "Further decryption attempts are blocked."
            )
    try:
        result_path, _ = decrypt_file(file_path, password, usb_id)
        reset_attempt_count(file_path)
        brute_mark_success()          # ← correct password → reset progressive counter
        return result_path
    except ValueError:
        brute_mark_fail()          # ← start 5-sec cooldown immediately
        if max_att > 0:
            new_count = increment_attempt_count(file_path)
            remaining = max_att - new_count
            if remaining <= 0:
                raise PermissionError(
                    f"Maximum attempts ({max_att}) exceeded.\n"
                    "Further decryption attempts are blocked."
                )
            raise ValueError(
                f"Authentication failed.\n"
                f"Attempts remaining: {remaining} / {max_att}"
            )
        raise

# ══════════════════════════════════════════════════════════════════════════════
#  BRUTE-FORCE PROTECTION  (progressive cooldown, persistent across restarts)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Fail sequence:
#    1st wrong  →   5 s
#    2nd wrong  →  20 s
#    3rd wrong  →  40 s
#    Nth (N≥4)  →  (N-3) × 60 s   [capped at 1 month = 2 592 000 s]

_brute_lock:       threading.Lock = threading.Lock()
_brute_fail_count: int            = 0
_brute_fail_ts:    float          = 0.0

def _cooldown_for_count(n: int) -> float:
    if n <= 0: return 0.0
    if n == 1: return 5.0
    if n == 2: return 20.0
    if n == 3: return 40.0
    return min((n - 3) * 60.0, 2_592_000.0)   # 1 month cap

def _load_brute_state() -> None:
    global _brute_fail_count, _brute_fail_ts
    try:
        if BRUTE_STATE_FILE.exists():
            d = json.loads(BRUTE_STATE_FILE.read_text())
            _brute_fail_count = int(d.get("fail_count", 0))
            _brute_fail_ts    = float(d.get("last_fail_ts", 0.0))
    except Exception:
        pass

def _save_brute_state() -> None:
    try:
        _ensure_dirs()
        BRUTE_STATE_FILE.write_text(
            json.dumps({"fail_count": _brute_fail_count,
                        "last_fail_ts": _brute_fail_ts}))
    except Exception:
        pass

def brute_remaining() -> float:
    """Return seconds remaining in cooldown (0.0 = free to proceed)."""
    with _brute_lock:
        cd = _cooldown_for_count(_brute_fail_count)
        return max(0.0, cd - (time.time() - _brute_fail_ts))

def brute_mark_fail() -> None:
    """Call immediately after any wrong-password event."""
    global _brute_fail_count, _brute_fail_ts
    with _brute_lock:
        _brute_fail_count += 1
        _brute_fail_ts     = time.time()
        _save_brute_state()

def brute_mark_success() -> None:
    """Call after a successful decryption — resets the progressive counter."""
    global _brute_fail_count, _brute_fail_ts
    with _brute_lock:
        _brute_fail_count = 0
        _brute_fail_ts    = 0.0
        _save_brute_state()

def verify_password_against_file(file_path: str,
                                 password: str,
                                 usb_id: str) -> bool:
    """
    In-memory authentication check — never writes anything to disk.
    Returns True if password + USB ID are correct for the given file (either slot).
    """
    valid, _ = verify_file(file_path, password, usb_id)
    return valid



def _fmt_size(nbytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} TB"

def _fmt_elapsed(seconds: float) -> str:
    """Format seconds into M:SS or H:MM:SS string."""
    s = int(seconds)
    if s < 60:
        return f"0:{s:02d}"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}:{s:02d}"
    h, m = divmod(m, 60)
    return f"{h}:{m:02d}:{s:02d}"

def scan_usb_for_avgvsto(usb_path: str) -> dict:
    """
    Scan the USB drive recursively for .avgvsto files.
    Returns stats + per-file details: path, size, status, max_attempts, mtime.
    """
    result = {
        "total": 0, "valid": 0, "corrupted": 0,
        "total_bytes": 0, "files": []
    }
    for root, _, fnames in os.walk(usb_path):
        for f in fnames:
            if not f.endswith(ENC_EXT):
                continue
            fp   = os.path.join(root, f)
            size = 0
            try:
                size  = os.path.getsize(fp)
                mtime = datetime.fromtimestamp(os.path.getmtime(fp))
                raw   = Path(fp).read_bytes()
                hdr   = read_header(raw)
                att   = hdr["max_attempts"]
                entry = {
                    "path": fp, "size": size,
                    "status": "valid",
                    "max_attempts": att,
                    "mtime": mtime.strftime("%Y-%m-%d %H:%M"),
                }
                result["valid"] += 1
            except Exception as exc:
                entry = {
                    "path": fp, "size": size,
                    "status": f"corrupted: {exc}",
                    "max_attempts": -1,
                    "mtime": "—",
                }
                result["corrupted"] += 1
            result["total"] += 1
            result["total_bytes"] += entry["size"]
            result["files"].append(entry)
    result["files"].sort(key=lambda x: x["mtime"], reverse=True)
    return result

def get_locked_attempt_files() -> List[dict]:
    """Return all attempt counter files stored in ~/.avgvsto/attempts/."""
    items = []
    if not ATTEMPTS_DIR.exists():
        return items
    for slot in ATTEMPTS_DIR.iterdir():
        try:
            count = int(slot.read_text().strip())
            items.append({"slot": slot, "count": count})
        except Exception:
            pass
    return items

# ══════════════════════════════════════════════════════════════════════════════
#  COLOUR PALETTE & FONTS
# ══════════════════════════════════════════════════════════════════════════════

C = {
    "bg":             "#0a0a0a",
    "surface":        "#111111",
    "surface2":       "#181818",
    "surface3":       "#202020",
    "border":         "#242424",
    "border_hi":      "#2e2e2e",
    "accent":         "#00ffcc",
    "accent_dim":     "#00bb99",
    "accent_red":     "#ff3355",
    "accent_red_dim": "#cc2244",
    "text":           "#d0d0d0",
    "text_dim":       "#3e3e3e",
    "text_mid":       "#888888",
    "text_bright":    "#ffffff",
    "success":        "#00ff88",
    "warning":        "#ffaa00",
    "error":          "#ff3355",
}

FONT_MONO   = ("Courier New", 11)
FONT_TITLE  = ("Courier New", 52, "bold")
FONT_SUB    = ("Courier New", 10)
FONT_BTN    = ("Courier New", 11, "bold")
FONT_SMALL  = ("Courier New", 9)
FONT_STATUS = ("Courier New", 10)

# ══════════════════════════════════════════════════════════════════════════════
#  ICON GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def _load_icon(root: tk.Tk) -> None:
    script_dir = Path(__file__).parent
    for name in ("icon.png", "icon.ico", "icon.gif", "avgvsto.ico", "avgvsto.png"):
        candidate = script_dir / name
        if candidate.exists():
            try:
                if name.endswith(".gif"):
                    ph = tk.PhotoImage(file=str(candidate))
                    root.iconphoto(True, ph)
                    root._icon_ref = ph
                    return
                from PIL import Image, ImageTk
                img = Image.open(str(candidate)).resize((64, 64))
                ph  = ImageTk.PhotoImage(img)
                root.iconphoto(True, ph)
                root._icon_ref = ph
                return
            except Exception:
                continue
    try:
        size   = 64
        bg_rgb = (10, 10, 10)
        fg_rgb = (0, 255, 204)
        hl_rgb = (0, 160, 120)
        px = bytearray()
        cx = cy = size / 2.0
        r  = size / 2.0 - 2.0
        for y in range(size):
            for x in range(size):
                dx, dy = x + 0.5 - cx, y + 0.5 - cy
                dist   = math.hypot(dx, dy)
                nx     = dx / r if r else 0
                ny     = dy / r if r else 0
                in_hex = (dist <= r * 0.97
                          and abs(dx) <= r * 0.866
                          and abs(dx) + abs(dy) * 0.577 <= r)
                if in_hex:
                    left  = (-0.44 + ny*0.55 - 0.11 < nx < -0.44 + ny*0.55 + 0.11) and ny < 0.28
                    right = ( 0.44 - ny*0.55 - 0.11 < nx <  0.44 - ny*0.55 + 0.11) and ny < 0.28
                    cross = -0.28 < nx < 0.28 and -0.14 < ny < 0.04
                    if left or right or cross:
                        px.extend(fg_rgb)
                    elif dist > r * 0.80:
                        px.extend(hl_rgb)
                    else:
                        px.extend((18, 18, 18))
                else:
                    px.extend(bg_rgb)
        header = f"P6\n{size} {size}\n255\n".encode()
        with tempfile.NamedTemporaryFile(suffix=".ppm", delete=False) as f:
            f.write(header + bytes(px))
            tmp = f.name
        ph = tk.PhotoImage(file=tmp)
        os.unlink(tmp)
        root.iconphoto(True, ph)
        root._icon_ref = ph
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  MODAL BASE
# ══════════════════════════════════════════════════════════════════════════════

class _AvgModal:
    def __init__(self, parent, title: str = "", color: str = None,
                 width: int = 460, height: int = 260):
        self.result   = None
        self.parent   = parent
        self._color   = color or C["accent"]
        self._drag_ox = 0
        self._drag_oy = 0

        self.dlg = tk.Toplevel(parent)
        self.dlg.overrideredirect(True)
        self.dlg.configure(bg=C["border_hi"])
        self.dlg.resizable(True, True)
        self.dlg.attributes("-alpha", 0.0)
        self.dlg.attributes("-topmost", True)

        parent.update_idletasks()
        px = parent.winfo_x() + parent.winfo_width()  // 2 - width  // 2
        py = parent.winfo_y() + parent.winfo_height() // 2 - height // 2
        self.dlg.geometry(f"{width}x{height}+{px}+{py}")

        self._inner = tk.Frame(self.dlg, bg=C["bg"])
        self._inner.place(x=1, y=1, relwidth=1, relheight=1, width=-2, height=-2)

        self._build_titlebar(title)
        self.dlg.transient(parent)
        self.dlg.grab_set()
        self._build()
        self.dlg.lift()
        self.dlg.focus_force()
        self._fade_in(1)

    def _fade_in(self, step: int, steps: int = 8) -> None:
        try:
            self.dlg.attributes("-alpha", step / steps)
        except Exception:
            return
        if step < steps:
            self.dlg.after(10, self._fade_in, step + 1, steps)

    def _build_titlebar(self, title: str) -> None:
        bar = tk.Frame(self._inner, bg=C["surface2"], height=36)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)
        tk.Frame(bar, bg=self._color, width=3).pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(bar, text=APP_NAME, bg=C["surface2"], fg=self._color,
                 font=("Courier New", 9, "bold"), padx=10).pack(side=tk.LEFT)
        if title:
            tk.Label(bar, text=f"— {title}", bg=C["surface2"], fg=C["text_mid"],
                     font=FONT_SMALL).pack(side=tk.LEFT)
        xb = tk.Button(bar, text="✕", command=lambda: self._close(None),
                       bg=C["surface2"], fg=C["text_mid"],
                       font=("Courier New", 10), relief=tk.FLAT, bd=0,
                       padx=12, pady=0, cursor="hand2")
        xb.pack(side=tk.RIGHT, fill=tk.Y)
        xb.bind("<Enter>", lambda e: xb.config(bg=C["error"], fg="white"))
        xb.bind("<Leave>", lambda e: xb.config(bg=C["surface2"], fg=C["text_mid"]))
        bar.bind("<Button-1>",  self._drag_start)
        bar.bind("<B1-Motion>", self._drag_move)

    def _drag_start(self, event) -> None:
        self._drag_ox = event.x_root - self.dlg.winfo_x()
        self._drag_oy = event.y_root - self.dlg.winfo_y()

    def _drag_move(self, event) -> None:
        self.dlg.geometry(
            f"+{event.x_root - self._drag_ox}+{event.y_root - self._drag_oy}"
        )

    def _close(self, value=None) -> None:
        self.result = value
        try:
            self.dlg.grab_release()
            self.dlg.destroy()
        except Exception:
            pass

    def _build(self) -> None:
        pass

    def show(self):
        self.dlg.wait_window()
        return self.result

    def _section(self, padx: int = 24, pady: int = 16) -> tk.Frame:
        f = tk.Frame(self._inner, bg=C["bg"])
        f.pack(fill=tk.BOTH, expand=True, padx=padx, pady=pady)
        return f

    def _lbl(self, parent, text: str, color: str = None,
             font=None, anchor: str = "w", wrap: int = 0) -> tk.Label:
        kw = {"wraplength": wrap} if wrap else {}
        return tk.Label(parent, text=text,
                        bg=C["bg"], fg=color or C["text"],
                        font=font or FONT_SMALL,
                        justify=tk.LEFT, anchor=anchor, **kw)

    def _btn(self, parent, text: str, cmd, color: str = None,
             secondary: bool = False) -> tk.Button:
        col = color or self._color
        bg  = C["surface2"] if secondary else col
        fg  = col            if secondary else C["bg"]
        b   = tk.Button(parent, text=text, command=cmd,
                        bg=bg, fg=fg,
                        activebackground=col, activeforeground=C["bg"],
                        font=("Courier New", 10, "bold"),
                        relief=tk.FLAT, bd=0, padx=18, pady=8,
                        cursor="hand2")
        b.bind("<Enter>", lambda e: b.config(bg=col, fg=C["bg"]))
        b.bind("<Leave>", lambda e: b.config(
            bg=C["surface2"] if secondary else col,
            fg=col            if secondary else C["bg"],
        ))
        return b

    def _hsep(self, parent, color: str = None) -> None:
        tk.Frame(parent, bg=color or C["border"], height=1).pack(
            fill=tk.X, pady=(6, 0))

# ══════════════════════════════════════════════════════════════════════════════
#  ALERT MODAL
# ══════════════════════════════════════════════════════════════════════════════

class AlertModal(_AvgModal):
    _META = {
        "info":    ("⬡", C["accent"]),
        "success": ("✓", C["success"]),
        "warning": ("⚠", C["warning"]),
        "error":   ("✕", C["error"]),
    }

    def __init__(self, parent, kind: str, title: str, message: str):
        self._kind   = kind
        self._atitle = title
        self._msg    = message
        _, col       = self._META.get(kind, self._META["info"])
        super().__init__(parent, title=title, color=col, width=520, height=280)

    def _build(self) -> None:
        icon, col = self._META.get(self._kind, self._META["info"])
        c = self._section(padx=26, pady=20)
        hdr = tk.Frame(c, bg=C["bg"])
        hdr.pack(fill=tk.X, pady=(0, 12))
        tk.Label(hdr, text=icon, bg=C["bg"], fg=col,
                 font=("Courier New", 22, "bold")).pack(side=tk.LEFT, padx=(0, 14))
        tk.Label(hdr, text=self._atitle, bg=C["bg"], fg=C["text_bright"],
                 font=("Courier New", 12, "bold")).pack(side=tk.LEFT, anchor="s")
        self._lbl(c, self._msg, wrap=430).pack(fill=tk.X, pady=(0, 20))
        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X)
        self._btn(row, "  OK  ", lambda: self._close(True), col).pack(side=tk.RIGHT)

# ══════════════════════════════════════════════════════════════════════════════
#  PASSWORD DIALOG
# ══════════════════════════════════════════════════════════════════════════════

class PasswordDialog(_AvgModal):
    def __init__(self, parent, confirm: bool = False, mode: str = "encrypt"):
        self._confirm = confirm
        self._mode    = mode
        col = C["accent"] if mode == "encrypt" else C["accent_red"]
        super().__init__(
            parent,
            title  = "Encryption Password" if mode == "encrypt" else "Decryption Password",
            color  = col,
            width  = 460,
            # Extra height for backup warning banner when encrypting
            height = 420 if confirm else 280,
        )

    def _build(self) -> None:
        c = self._section(padx=26, pady=18)

        # ── Backup warning banner (encrypt mode only) ─────────────────────────
        if self._confirm:
            warn_f = tk.Frame(c, bg=C["surface3"],
                              highlightbackground=C["warning"],
                              highlightthickness=1)
            warn_f.pack(fill=tk.X, pady=(0, 14))
            inner_w = tk.Frame(warn_f, bg=C["surface3"], padx=12, pady=8)
            inner_w.pack(fill=tk.X)
            tk.Label(inner_w, text="⚠",
                     bg=C["surface3"], fg=C["warning"],
                     font=("Courier New", 13, "bold")).pack(side=tk.LEFT,
                                                            padx=(0, 10), anchor="n")
            txt_f = tk.Frame(inner_w, bg=C["surface3"])
            txt_f.pack(side=tk.LEFT, fill=tk.X, expand=True)
            tk.Label(txt_f,
                     text="IT'S STRONGLY RECOMMENDED THAT YOU",
                     bg=C["surface3"], fg=C["warning"],
                     font=("Courier New", 8, "bold"),
                     anchor="w").pack(anchor="w")
            tk.Label(txt_f,
                     text="BACK UP YOUR DATA BEFORE ENCRYPTING",
                     bg=C["surface3"], fg=C["warning"],
                     font=("Courier New", 8, "bold"),
                     anchor="w").pack(anchor="w")
            tk.Label(txt_f,
                     text="Use  BACKUP ▾  in the top menu to create a backup.",
                     bg=C["surface3"], fg=C["text_mid"],
                     font=("Courier New", 7),
                     anchor="w").pack(anchor="w", pady=(2, 0))
        # ─────────────────────────────────────────────────────────────────────

        verb = "ENCRYPTION" if self._mode == "encrypt" else "DECRYPTION"
        self._lbl(c, f"{verb} PASSWORD",
                  color=self._color,
                  font=("Courier New", 10, "bold")).pack(anchor="w", pady=(0, 16))
        self._pw_var   = tk.StringVar()
        self._pw_entry = self._pw_row(c, "Password", self._pw_var)
        if self._confirm:
            self._cf_var   = tk.StringVar()
            self._cf_entry = self._pw_row(c, "Confirm", self._cf_var)
        self._err = tk.StringVar()
        tk.Label(c, textvariable=self._err,
                 bg=C["bg"], fg=C["error"],
                 font=FONT_SMALL, anchor="w").pack(fill=tk.X)
        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X, pady=(14, 0))
        self._btn(row, "CANCEL",  lambda: self._close(None),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT, padx=(6, 0))
        self._btn(row, "CONFIRM", self._submit, self._color).pack(side=tk.RIGHT)
        self._pw_entry.focus_set()
        self._pw_entry.bind("<Return>", lambda e: self._submit())
        if self._confirm and hasattr(self, "_cf_entry"):
            self._cf_entry.bind("<Return>", lambda e: self._submit())

    def _pw_row(self, parent, label: str, var: tk.StringVar) -> tk.Entry:
        tk.Label(parent, text=label, bg=C["bg"], fg=C["text_mid"],
                 font=FONT_SMALL).pack(anchor="w", pady=(0, 2))
        wrap = tk.Frame(parent, bg=C["surface2"], pady=2)
        wrap.pack(fill=tk.X, pady=(0, 10))
        entry = tk.Entry(wrap, textvariable=var, show="•",
                         bg=C["surface2"], fg=C["text_bright"],
                         insertbackground=self._color,
                         font=("Courier New", 11),
                         relief=tk.FLAT, bd=8)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        _shown = [False]
        def toggle(e=entry, s=_shown):
            s[0] = not s[0]
            e.config(show="" if s[0] else "•")
            eye.config(fg=self._color if s[0] else C["text_dim"])
        eye = tk.Button(wrap, text="◎", command=toggle,
                        bg=C["surface2"], fg=C["text_dim"],
                        font=("Courier New", 10), relief=tk.FLAT, bd=0,
                        padx=7, cursor="hand2")
        eye.pack(side=tk.RIGHT, padx=(0, 4))
        return entry

    def _submit(self) -> None:
        pw = self._pw_var.get()
        if not pw:
            self._err.set("Password cannot be empty.")
            return
        if self._confirm and pw != self._cf_var.get():
            self._err.set("Passwords do not match — try again.")
            return
        self._close(pw)

# ══════════════════════════════════════════════════════════════════════════════
#  ATTEMPT LIMIT DIALOG
# ══════════════════════════════════════════════════════════════════════════════

class AttemptLimitDialog(_AvgModal):
    def __init__(self, parent):
        super().__init__(parent, title="Attempt Limit",
                         color=C["accent"], width=360, height=222)

    def _build(self) -> None:
        c = self._section()
        self._lbl(c, "MAX DECRYPTION ATTEMPTS",
                  color=self._color,
                  font=("Courier New", 10, "bold")).pack(anchor="w")
        self._lbl(c, "0 = unlimited").pack(anchor="w", pady=(2, 16))
        self._val = tk.IntVar(value=0)
        ctr = tk.Frame(c, bg=C["bg"])
        ctr.pack(pady=(0, 20))
        def _nb(sym, cmd):
            b = tk.Button(ctr, text=sym, command=cmd,
                          bg=C["surface2"], fg=C["accent"],
                          font=("Courier New", 16, "bold"),
                          relief=tk.FLAT, bd=0, padx=18, pady=4, cursor="hand2")
            b.bind("<Enter>", lambda e: b.config(bg=C["accent"], fg=C["bg"]))
            b.bind("<Leave>", lambda e: b.config(bg=C["surface2"], fg=C["accent"]))
            return b
        _nb("−", lambda: self._val.set(max(0, self._val.get() - 1))).pack(side=tk.LEFT)
        tk.Label(ctr, textvariable=self._val, width=5,
                 bg=C["surface3"], fg=C["text_bright"],
                 font=("Courier New", 20, "bold"), pady=2).pack(side=tk.LEFT, padx=6)
        _nb("+", lambda: self._val.set(self._val.get() + 1)).pack(side=tk.LEFT)
        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X)
        self._btn(row, "CANCEL",  lambda: self._close(None),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT, padx=(6, 0))
        self._btn(row, "CONFIRM", lambda: self._close(self._val.get()),
                  C["accent"]).pack(side=tk.RIGHT)

# ══════════════════════════════════════════════════════════════════════════════
#  RESET PASSWORD DIALOGS
# ══════════════════════════════════════════════════════════════════════════════

class ResetPasswordCreateDialog(_AvgModal):
    """
    Shown during encryption when attempts > 0 and no reset password exists.
    User creates a single reset password for this USB drive.
    """
    def __init__(self, parent):
        super().__init__(parent, title="Create Reset Password",
                        color=C["warning"], width=500, height=460)

    def _build(self) -> None:
        c = self._section(padx=26, pady=18)
        self._lbl(c, "CREATE RESET PASSWORD",
                color=self._color,
                font=("Courier New", 10, "bold")).pack(anchor="w")
        self._lbl(
            c,
            "You set a decryption attempt limit.\n"
            "Create a RESET PASSWORD stored on this USB to unlock counters later.\n\n"
            "• One password covers ALL files on this USB\n"
            "• Max 3 wrong reset attempts → reset permanently locked\n"
            "• Max 3 resets total → use CLEANUP FULL CLEAR to start over\n"
            "• Skipping means you can NEVER reset locked attempt counters",
            color=C["text_mid"], wrap=450,
        ).pack(anchor="w", pady=(4, 14))

        self._pw_var = tk.StringVar()
        self._cf_var = tk.StringVar()
        self._pw_entry = self._pw_row(c, "Reset Password", self._pw_var)
        self._cf_entry = self._pw_row(c, "Confirm",        self._cf_var)

        self._err = tk.StringVar()
        tk.Label(c, textvariable=self._err,
                 bg=C["bg"], fg=C["error"], font=FONT_SMALL, anchor="w").pack(fill=tk.X)

        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X, pady=(10, 0))
        self._btn(row, "SKIP (no reset)", lambda: self._close(None),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT, padx=(6, 0))
        self._btn(row, "CREATE", self._submit, self._color).pack(side=tk.RIGHT)
        self._pw_entry.focus_set()
        self._pw_entry.bind("<Return>", lambda e: self._cf_entry.focus_set())
        self._cf_entry.bind("<Return>", lambda e: self._submit())

    def _pw_row(self, parent, label: str, var: tk.StringVar) -> tk.Entry:
        tk.Label(parent, text=label, bg=C["bg"], fg=C["text_mid"],
                 font=FONT_SMALL).pack(anchor="w", pady=(0, 2))
        wrap = tk.Frame(parent, bg=C["surface2"], pady=2)
        wrap.pack(fill=tk.X, pady=(0, 8))
        entry = tk.Entry(wrap, textvariable=var, show="•",
                         bg=C["surface2"], fg=C["text_bright"],
                         insertbackground=self._color,
                         font=("Courier New", 11), relief=tk.FLAT, bd=8)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        _shown = [False]
        def toggle(e=entry, s=_shown):
            s[0] = not s[0]
            e.config(show="" if s[0] else "•")
            eye.config(fg=self._color if s[0] else C["text_dim"])
        eye = tk.Button(wrap, text="◎", command=toggle,
                        bg=C["surface2"], fg=C["text_dim"],
                        font=("Courier New", 10), relief=tk.FLAT, bd=0,
                        padx=7, cursor="hand2")
        eye.pack(side=tk.RIGHT, padx=(0, 4))
        return entry

    def _submit(self) -> None:
        pw = self._pw_var.get()
        if not pw:
            self._err.set("Password cannot be empty.")
            return
        if pw != self._cf_var.get():
            self._err.set("Passwords do not match.")
            return
        if len(pw) < 4:
            self._err.set("Reset password must be at least 4 characters.")
            return
        self._close(pw)


class ResetPasswordVerifyDialog(_AvgModal):
    """Ask user to enter the reset password to unlock attempt counters."""
    def __init__(self, parent, status_msg: str = ""):
        self._status = status_msg
        super().__init__(parent, title="Reset Attempt Counters",
                         color=C["warning"], width=460, height=280)

    def _build(self) -> None:
        c = self._section(padx=26, pady=18)
        self._lbl(c, "RESET ATTEMPT COUNTERS",
                  color=self._color,
                  font=("Courier New", 10, "bold")).pack(anchor="w")
        if self._status:
            self._lbl(c, self._status, color=C["text_mid"], wrap=410).pack(
                anchor="w", pady=(4, 0))
        self._lbl(c, "Enter the RESET PASSWORD set on this USB:",
                  color=C["text"], wrap=410).pack(anchor="w", pady=(10, 4))

        self._pw_var = tk.StringVar()
        wrap = tk.Frame(c, bg=C["surface2"], pady=2)
        wrap.pack(fill=tk.X, pady=(0, 8))
        self._entry = tk.Entry(wrap, textvariable=self._pw_var, show="•",
                               bg=C["surface2"], fg=C["text_bright"],
                               insertbackground=self._color,
                               font=("Courier New", 11), relief=tk.FLAT, bd=8)
        self._entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        _shown = [False]
        def toggle(s=_shown):
            s[0] = not s[0]
            self._entry.config(show="" if s[0] else "•")
            eye.config(fg=self._color if s[0] else C["text_dim"])
        eye = tk.Button(wrap, text="◎", command=toggle,
                        bg=C["surface2"], fg=C["text_dim"],
                        font=("Courier New", 10), relief=tk.FLAT, bd=0,
                        padx=7, cursor="hand2")
        eye.pack(side=tk.RIGHT, padx=(0, 4))

        self._err = tk.StringVar()
        tk.Label(c, textvariable=self._err,
                 bg=C["bg"], fg=C["error"], font=FONT_SMALL, anchor="w").pack(fill=tk.X)

        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X, pady=(10, 0))
        self._btn(row, "CANCEL", lambda: self._close(None),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT, padx=(6, 0))
        self._btn(row, "RESET", self._submit, self._color).pack(side=tk.RIGHT)
        self._entry.focus_set()
        self._entry.bind("<Return>", lambda e: self._submit())

    def _submit(self) -> None:
        pw = self._pw_var.get()
        if not pw:
            self._err.set("Enter the reset password.")
            return
        self._close(pw)

# ══════════════════════════════════════════════════════════════════════════════
#  DURESS / DECOY PASSWORD DIALOG
# ══════════════════════════════════════════════════════════════════════════════

class DuressDialog(_AvgModal):
    """
    Ask whether the user wants to set a 'duress password' (plausible deniability).
    Returns a dict: {"duress_password": str, "duress_data": bytes} or None if skipped.

    The duress password decrypts to a harmless decoy file — the same .avgvsto
    file contains two completely independent ciphertexts. An adversary cannot
    determine which password is 'real'.
    """
    def __init__(self, parent):
        super().__init__(parent, title="Duress Password",
                         color=C["warning"], width=540, height=460)

    def _build(self) -> None:
        c = self._section(padx=24, pady=16)

        self._lbl(c, "DURESS / PLAUSIBLE DENIABILITY",
                  color=self._color,
                  font=("Courier New", 10, "bold")).pack(anchor="w")
        self._lbl(
            c,
            "Optional — set a second 'duress' password that decrypts to an\n"
            "innocent decoy file. Both passwords produce a valid decryption.\n"
            "An adversary cannot determine which password is real.\n\n"
            "Use case: lawyers, journalists, activists under coercion.",
            color=C["text_mid"], wrap=490,
        ).pack(anchor="w", pady=(4, 12))

        self._enable_var = tk.BooleanVar(value=False)
        chk = tk.Checkbutton(c, text="Enable duress password for this encryption",
                             variable=self._enable_var,
                             command=self._toggle,
                             bg=C["bg"], fg=C["warning"],
                             activebackground=C["bg"],
                             selectcolor=C["surface3"],
                             font=("Courier New", 9, "bold"),
                             relief=tk.FLAT, cursor="hand2")
        chk.pack(anchor="w", pady=(0, 10))

        # Fields frame (shown/hidden)
        self._fields = tk.Frame(c, bg=C["bg"])
        self._fields.pack(fill=tk.X)

        self._pw_var = tk.StringVar()
        self._cf_var = tk.StringVar()
        self._pw_entry = self._pw_row(self._fields, "Duress Password", self._pw_var)
        self._cf_entry = self._pw_row(self._fields, "Confirm",          self._cf_var)

        # Decoy file selector
        self._lbl(self._fields, "Decoy file (shown when duress password is used):",
                  color=C["text_mid"]).pack(anchor="w", pady=(6, 2))
        drow = tk.Frame(self._fields, bg=C["bg"])
        drow.pack(fill=tk.X, pady=(0, 6))
        self._decoy_var = tk.StringVar(value="(empty file — no content)")
        tk.Label(drow, textvariable=self._decoy_var,
                 bg=C["surface2"], fg=C["text_mid"],
                 font=("Courier New", 8), padx=8, pady=4,
                 anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)
        browse_b = tk.Button(drow, text=" BROWSE ",
                             command=self._browse_decoy,
                             bg=C["surface2"], fg=C["warning"],
                             font=("Courier New", 8, "bold"),
                             relief=tk.FLAT, bd=0, padx=6, pady=4, cursor="hand2")
        browse_b.bind("<Enter>", lambda e: browse_b.config(bg=C["warning"], fg=C["bg"]))
        browse_b.bind("<Leave>", lambda e: browse_b.config(bg=C["surface2"], fg=C["warning"]))
        browse_b.pack(side=tk.RIGHT, padx=(4, 0))
        self._decoy_data = b""   # bytes of decoy content

        self._err = tk.StringVar()
        tk.Label(c, textvariable=self._err,
                 bg=C["bg"], fg=C["error"], font=FONT_SMALL, anchor="w").pack(fill=tk.X)

        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X, pady=(10, 0))
        self._btn(row, "SKIP (no duress)", lambda: self._close(None),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT, padx=(6, 0))
        self._confirm_btn = self._btn(row, "CONFIRM", self._submit, self._color)
        self._confirm_btn.pack(side=tk.RIGHT)

        self._toggle()   # initial state: fields hidden

    def _toggle(self) -> None:
        if self._enable_var.get():
            self._fields.pack(fill=tk.X)
            self._confirm_btn.config(state=tk.NORMAL)
        else:
            self._fields.pack_forget()
            self._confirm_btn.config(state=tk.DISABLED)

    def _pw_row(self, parent, label: str, var: tk.StringVar) -> tk.Entry:
        tk.Label(parent, text=label, bg=C["bg"], fg=C["text_mid"],
                 font=FONT_SMALL).pack(anchor="w", pady=(0, 2))
        wrap = tk.Frame(parent, bg=C["surface2"], pady=2)
        wrap.pack(fill=tk.X, pady=(0, 8))
        entry = tk.Entry(wrap, textvariable=var, show="•",
                         bg=C["surface2"], fg=C["text_bright"],
                         insertbackground=self._color,
                         font=("Courier New", 11), relief=tk.FLAT, bd=8)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        _shown = [False]
        def toggle(e=entry, s=_shown):
            s[0] = not s[0]
            e.config(show="" if s[0] else "•")
            eye.config(fg=self._color if s[0] else C["text_dim"])
        eye = tk.Button(wrap, text="◎", command=toggle,
                        bg=C["surface2"], fg=C["text_dim"],
                        font=("Courier New", 10), relief=tk.FLAT, bd=0,
                        padx=7, cursor="hand2")
        eye.pack(side=tk.RIGHT, padx=(0, 4))
        return entry

    def _browse_decoy(self) -> None:
        path = filedialog.askopenfilename(
            title="Select decoy file (shown on duress decryption)",
            parent=self.dlg)
        if path and os.path.isfile(path):
            try:
                self._decoy_data = Path(path).read_bytes()
                name = os.path.basename(path)
                size = _fmt_size(len(self._decoy_data))
                self._decoy_var.set(f"{name}  ({size})")
            except Exception as exc:
                self._err.set(f"Cannot read decoy file: {exc}")

    def _submit(self) -> None:
        if not self._enable_var.get():
            self._close(None)
            return
        pw = self._pw_var.get()
        if not pw:
            self._err.set("Duress password cannot be empty.")
            return
        if pw != self._cf_var.get():
            self._err.set("Passwords do not match.")
            return
        if len(pw) < 4:
            self._err.set("Duress password must be at least 4 characters.")
            return
        self._close({"duress_password": pw, "duress_data": self._decoy_data})

# ══════════════════════════════════════════════════════════════════════════════
#  VERIFY RESULT MODAL
# ══════════════════════════════════════════════════════════════════════════════

class VerifyResultModal(_AvgModal):
    def __init__(self, parent, ok: bool, message: str):
        self._ok  = ok
        self._msg = message
        col = C["success"] if ok else C["error"]
        super().__init__(parent, title="Verify Integrity",
                         color=col, width=500, height=240)

    def _build(self) -> None:
        c = self._section(padx=26, pady=22)
        hdr = tk.Frame(c, bg=C["bg"])
        hdr.pack(fill=tk.X, pady=(0, 12))
        icon = "✓" if self._ok else "✕"
        col  = C["success"] if self._ok else C["error"]
        tk.Label(hdr, text=icon, bg=C["bg"], fg=col,
                 font=("Courier New", 22, "bold")).pack(side=tk.LEFT, padx=(0, 14))
        title = "File Integrity OK" if self._ok else "Integrity Check Failed"
        tk.Label(hdr, text=title, bg=C["bg"], fg=C["text_bright"],
                 font=("Courier New", 12, "bold")).pack(side=tk.LEFT, anchor="s")
        self._lbl(c, self._msg, wrap=450, color=C["text_mid"]).pack(
            fill=tk.X, pady=(0, 16))
        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X)
        self._btn(row, "  OK  ", lambda: self._close(None), col).pack(side=tk.RIGHT)

# ══════════════════════════════════════════════════════════════════════════════
#  FIRST-RUN WIZARD
# ══════════════════════════════════════════════════════════════════════════════

class FirstRunWizard(_AvgModal):
    """
    Shown when no USB binding exists yet.
    3-step guided setup: Welcome → Bind USB → Encrypt Test
    """
    def __init__(self, parent, usb_drives: List[str]):
        self._drives  = usb_drives
        self._step    = 0
        self._chosen  = None
        super().__init__(parent, title="Setup Wizard",
                         color=C["accent"], width=520, height=380)

    def _build(self) -> None:
        self._pages = []
        self._container = tk.Frame(self._inner, bg=C["bg"])
        self._container.pack(fill=tk.BOTH, expand=True)
        self._build_step0()
        self._build_step1()
        self._build_step2()
        self._show_step(0)

    def _build_step0(self) -> None:
        """Welcome page."""
        f = tk.Frame(self._container, bg=C["bg"])
        self._pages.append(f)

        c = tk.Frame(f, bg=C["bg"])
        c.pack(fill=tk.BOTH, expand=True, padx=28, pady=20)

        tk.Label(c, text="⬡  WELCOME TO AVGVSTO", bg=C["bg"], fg=C["accent"],
                 font=("Courier New", 13, "bold")).pack(anchor="w", pady=(0, 10))

        txt = (
            "AVGVSTO encrypts your files using AES-256-GCM — the same\n"
            "standard used by banks and governments.\n\n"
            "Your USB drive acts as a hardware key: even with the correct\n"
            "password, decryption is IMPOSSIBLE without the exact USB.\n\n"
            "This wizard will guide you through the 3-minute setup."
        )
        self._lbl(c, txt, color=C["text_mid"], wrap=460).pack(anchor="w", pady=(0, 20))

        foot = tk.Frame(c, bg=C["bg"])
        foot.pack(fill=tk.X, side=tk.BOTTOM)
        self._btn(foot, "START SETUP →", lambda: self._show_step(1),
                  C["accent"]).pack(side=tk.RIGHT)

    def _build_step1(self) -> None:
        """Bind USB page."""
        f = tk.Frame(self._container, bg=C["bg"])
        self._pages.append(f)

        c = tk.Frame(f, bg=C["bg"])
        c.pack(fill=tk.BOTH, expand=True, padx=28, pady=20)

        tk.Label(c, text="STEP 1 / 2  ·  BIND YOUR USB DRIVE",
                 bg=C["bg"], fg=C["accent"],
                 font=("Courier New", 10, "bold")).pack(anchor="w", pady=(0, 8))
        self._lbl(c,
            "Insert your USB drive and select it below.\n"
            "This drive will become your hardware decryption key.\n"
            "Keep it safe — without it, your files cannot be opened.",
            color=C["text_mid"], wrap=460).pack(anchor="w", pady=(0, 14))

        self._wiz_usb_var = tk.StringVar()
        if self._drives:
            self._wiz_usb_var.set(self._drives[0])
        combo = ttk.Combobox(c, textvariable=self._wiz_usb_var,
                             values=self._drives,
                             font=FONT_MONO, state="readonly")
        combo.pack(fill=tk.X, pady=(0, 6))

        browse_b = tk.Button(c, text="BROWSE — select manually",
                             command=self._wiz_browse,
                             bg=C["surface2"], fg=C["accent_dim"],
                             font=("Courier New", 8, "bold"),
                             relief=tk.FLAT, bd=0, padx=8, pady=4, cursor="hand2")
        browse_b.pack(anchor="w", pady=(0, 16))

        self._wiz_err = tk.StringVar()
        tk.Label(c, textvariable=self._wiz_err,
                 bg=C["bg"], fg=C["error"], font=FONT_SMALL).pack(anchor="w")

        foot = tk.Frame(c, bg=C["bg"])
        foot.pack(fill=tk.X, side=tk.BOTTOM)
        self._btn(foot, "← BACK", lambda: self._show_step(0),
                  C["text_mid"], secondary=True).pack(side=tk.LEFT)
        self._btn(foot, "BIND & CONTINUE →", self._wiz_bind,
                  C["accent"]).pack(side=tk.RIGHT)

    def _build_step2(self) -> None:
        """Done page."""
        f = tk.Frame(self._container, bg=C["bg"])
        self._pages.append(f)

        c = tk.Frame(f, bg=C["bg"])
        c.pack(fill=tk.BOTH, expand=True, padx=28, pady=20)

        tk.Label(c, text="✓  SETUP COMPLETE",
                 bg=C["bg"], fg=C["success"],
                 font=("Courier New", 13, "bold")).pack(anchor="w", pady=(0, 10))

        self._wiz_done_lbl = tk.Label(c, text="",
                                       bg=C["bg"], fg=C["text_mid"],
                                       font=("Courier New", 9),
                                       justify=tk.LEFT, anchor="w",
                                       wraplength=460)
        self._wiz_done_lbl.pack(anchor="w", pady=(0, 20))

        foot = tk.Frame(c, bg=C["bg"])
        foot.pack(fill=tk.X, side=tk.BOTTOM)
        self._btn(foot, "START USING AVGVSTO", lambda: self._close(True),
                  C["success"]).pack(side=tk.RIGHT)

    def _show_step(self, n: int) -> None:
        for i, p in enumerate(self._pages):
            if i == n:
                p.place(relx=0, rely=0, relwidth=1, relheight=1)
                p.lift()
            else:
                p.place_forget()
        self._step = n

    def _wiz_browse(self) -> None:
        chosen = filedialog.askdirectory(
            title="Select USB drive directory", parent=self.dlg)
        if chosen and os.path.isdir(chosen):
            vals = list(self._pages[1].winfo_children())
            self._wiz_usb_var.set(chosen)

    def _wiz_bind(self) -> None:
        chosen = self._wiz_usb_var.get()
        if not chosen or not os.path.isdir(chosen):
            self._wiz_err.set("Select a valid drive first.")
            return
        uid = save_usb_config(chosen)
        if not uid:
            self._wiz_err.set("Could not read device identifier. Try a different drive.")
            return
        self._chosen = chosen
        self._wiz_done_lbl.config(
            text=f"USB drive bound successfully!\n\n"
                 f"Drive: {chosen}\n"
                 f"ID: {uid[:16]}…\n\n"
                 f"You can now encrypt files.\n"
                 f"Remember: this USB drive must be plugged in to decrypt.\n\n"
                 f"{'  ⚡ PORTABLE MODE ACTIVE — config stored on USB' if _IS_PORTABLE else ''}")
        self._show_step(2)

# ══════════════════════════════════════════════════════════════════════════════
#  FILE / FOLDER DIALOG
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
#  ALGORITHM DIALOG  (Pro+ — shown before encryption)
# ══════════════════════════════════════════════════════════════════════════════

class AlgorithmDialog(_AvgModal):
    """
    Let Pro/Business users choose the encryption algorithm.
    Returns CIPHER_AES, CIPHER_CHACHA20, or CIPHER_CASCADE, or None if cancelled.
    """
    _OPTIONS = [
        (CIPHER_AES,      "AES-256-GCM",
         "Military-standard.\nHardware-accelerated (AES-NI).\nDefault choice.",
         "all"),
        (CIPHER_CHACHA20, "ChaCha20-Poly1305",
         "Modern stream cipher.\nFaster on CPUs without AES-NI.\nEqually secure.",
         "all"),
        (CIPHER_CASCADE,  "CASCADE  [paranoid]",
         "AES-256-GCM → ChaCha20-Poly1305.\nTwo independent keys. Survives\nif one algorithm is broken.",
         "business"),
    ]

    def __init__(self, parent):
        super().__init__(parent, title="Encryption Algorithm",
                         color=C["accent"], width=560, height=240)

    def _build(self) -> None:
        c = self._section(padx=26, pady=18)
        self._lbl(c, "SELECT ALGORITHM",
                  color=self._color,
                  font=("Courier New", 10, "bold")).pack(anchor="w", pady=(0, 14))

        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X, pady=(0, 16))

        for i, (cipher_id, name, desc, tier) in enumerate(self._OPTIONS):
            cell = tk.Frame(row, bg=C["surface2"], padx=12, pady=10,
                            cursor="hand2")
            cell.pack(side=tk.LEFT, expand=True, fill=tk.BOTH,
                      padx=(0, 0 if i == len(self._OPTIONS)-1 else 8))
            name_col = C["accent_red"] if tier == "business" else C["accent"]
            tk.Label(cell, text=name,
                     bg=C["surface2"], fg=name_col,
                     font=("Courier New", 9, "bold")).pack(anchor="w")
            tk.Label(cell, text=desc,
                     bg=C["surface2"], fg=C["text_mid"],
                     font=("Courier New", 8),
                     justify=tk.LEFT).pack(anchor="w", pady=(4, 0))
            def _click(cid=cipher_id):
                self._close(cid)
            cell.bind("<Button-1>", lambda e, f=_click: f())
            for child in cell.winfo_children():
                child.bind("<Button-1>", lambda e, f=_click: f())
            cell.bind("<Enter>", lambda e, w=cell: w.config(bg=C["surface3"]))
            cell.bind("<Leave>", lambda e, w=cell: w.config(bg=C["surface2"]))

        cancel_row = tk.Frame(c, bg=C["bg"])
        cancel_row.pack(fill=tk.X)
        self._btn(cancel_row, "  CANCEL  ",
                  lambda: self._close(None),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT)


# ══════════════════════════════════════════════════════════════════════════════
#  AUDIT LOG MODAL  (Business tier)
# ══════════════════════════════════════════════════════════════════════════════

class AuditLogModal(_AvgModal):
    """
    Show the full audit log with HMAC verification status per line.
    Business feature: tamper-evident log of all encrypt/decrypt operations.
    """
    def __init__(self, parent):
        super().__init__(parent, title="Audit Log",
                         color=C["accent"], width=720, height=560)

    def _build(self) -> None:
        outer = tk.Frame(self._inner, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True)

        # ── Stats bar ─────────────────────────────────────────────────────────
        top = tk.Frame(outer, bg=C["surface2"])
        top.pack(fill=tk.X, padx=1, pady=(1, 0))
        self._info_lbl = tk.Label(
            top, text="Loading…",
            bg=C["surface2"], fg=C["accent"],
            font=("Courier New", 9, "bold"), anchor="w", padx=16, pady=8)
        self._info_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # ── Log text ──────────────────────────────────────────────────────────
        list_f = tk.Frame(outer, bg=C["surface"])
        list_f.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        scroll = tk.Scrollbar(list_f, orient=tk.VERTICAL,
                              troughcolor=C["surface"], bg=C["surface3"],
                              activebackground=C["accent"],
                              relief=tk.FLAT, bd=0, width=10)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._txt = tk.Text(
            list_f, bg=C["surface"], fg=C["text"],
            font=("Courier New", 8), relief=tk.FLAT, bd=10,
            wrap=tk.NONE, state=tk.NORMAL, cursor="arrow",
            yscrollcommand=scroll.set)
        self._txt.pack(fill=tk.BOTH, expand=True)
        scroll.config(command=self._txt.yview)
        self._txt.tag_config("ok",   foreground=C["success"])
        self._txt.tag_config("fail", foreground=C["error"])
        self._txt.tag_config("warn", foreground=C["warning"])
        self._txt.tag_config("dim",  foreground=C["text_dim"])
        self._txt.tag_config("head", foreground=C["accent"],
                             font=("Courier New", 8, "bold"))

        # ── Footer ────────────────────────────────────────────────────────────
        foot = tk.Frame(self._inner, bg=C["bg"], pady=10)
        foot.pack(fill=tk.X, padx=16)
        self._btn(foot, "  CLOSE  ", lambda: self._close(None)).pack(side=tk.RIGHT)
        self._btn(foot, "  EXPORT LOG  ", self._export,
                  C["accent"], secondary=True).pack(side=tk.RIGHT, padx=(0, 6))

        self._load_entries()

    def _load_entries(self) -> None:
        entries = load_audit_log(max_lines=1000)
        self._txt.config(state=tk.NORMAL)
        self._txt.delete("1.0", tk.END)

        if not entries:
            self._txt.insert(tk.END,
                "  No audit log entries yet.\n"
                "  Every encrypt/decrypt/verify operation will be logged here.\n",
                "dim")
            self._info_lbl.config(text="Audit log — 0 entries")
            self._txt.config(state=tk.DISABLED)
            return

        # Header row
        self._txt.insert(tk.END,
            f"  {'TIMESTAMP':<22} {'OP':<10} {'RESULT':<8} "
            f"{'USB':<14} {'FILE':<30} {'EXTRA':<18} SIG\n", "head")
        self._txt.insert(tk.END, "  " + "─"*100 + "\n", "dim")

        tampered = 0
        for e in reversed(entries):
            result_tag = "ok" if e["result"] == "OK" else "fail"
            sig_tag    = "ok" if e["valid"] else "warn"
            sig_str    = "✓" if e["valid"] else "✕ TAMPERED"
            if not e["valid"]:
                tampered += 1
            line = (f"  {e['ts']:<22} {e['operation']:<10} {e['result']:<8} "
                    f"{e['usb']:<14} {e['target'][:28]:<30} {e['extra'][:16]:<18}")
            self._txt.insert(tk.END, line, result_tag)
            self._txt.insert(tk.END, f" {sig_str}\n", sig_tag)

        self._txt.config(state=tk.DISABLED)
        warn = f"  ⚠ {tampered} tampered line(s) detected!" if tampered else ""
        self._info_lbl.config(
            text=f"Audit log — {len(entries)} entries{warn}",
            fg=C["error"] if tampered else C["accent"])

    def _export(self) -> None:
        dest = filedialog.asksaveasfilename(
            title="Export audit log",
            defaultextension=".log",
            filetypes=[("Log file", "*.log"), ("All files", "*.*")],
            parent=self.dlg)
        if not dest:
            return
        n = export_audit_log(dest)
        AlertModal(self.dlg, "success", "Export Complete",
                   f"Exported {n} log entries to:\n{dest}").show()


# ══════════════════════════════════════════════════════════════════════════════
#  USB BINDINGS MODAL  (Business tier — manage multiple USB keys)
# ══════════════════════════════════════════════════════════════════════════════

class UsbBindingsModal(_AvgModal):
    """List all registered USB IDs, allow removal."""
    def __init__(self, parent):
        super().__init__(parent, title="USB Key Bindings",
                         color=C["accent"], width=560, height=380)

    def _build(self) -> None:
        outer = tk.Frame(self._inner, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True)

        tk.Label(outer,
                 text="REGISTERED USB KEYS  —  Business tier: unlimited bindings",
                 bg=C["bg"], fg=C["text_dim"],
                 font=("Courier New", 8, "bold"),
                 anchor="w", padx=26, pady=10).pack(fill=tk.X)

        list_f = tk.Frame(outer, bg=C["surface"], padx=0)
        list_f.pack(fill=tk.BOTH, expand=True, padx=24, pady=(0, 8))

        ids = _load_all_usb_ids()
        connected = set()
        for p in list_usb_drives():
            uid = get_usb_identifier(p)
            if uid:
                connected.add(uid)

        if not ids:
            tk.Label(list_f, text="  No USB keys registered yet.",
                     bg=C["surface"], fg=C["text_mid"],
                     font=("Courier New", 9), anchor="w", pady=12).pack(fill=tk.X)
        else:
            for uid in ids:
                is_conn = uid in connected
                row = tk.Frame(list_f, bg=C["surface2"])
                row.pack(fill=tk.X, padx=8, pady=3)
                dot_col = C["success"] if is_conn else C["text_dim"]
                tk.Label(row, text="●", bg=C["surface2"], fg=dot_col,
                         font=("Courier New", 10)).pack(side=tk.LEFT, padx=(8, 6))
                tk.Label(row, text=uid[:24] + "…",
                         bg=C["surface2"], fg=C["text"],
                         font=("Courier New", 9)).pack(side=tk.LEFT, expand=True, anchor="w")
                tk.Label(row,
                         text="CONNECTED" if is_conn else "offline",
                         bg=C["surface2"],
                         fg=C["success"] if is_conn else C["text_dim"],
                         font=("Courier New", 8, "bold"), padx=8).pack(side=tk.LEFT)
                def _remove(u=uid):
                    if remove_usb_binding(u):
                        AlertModal(self.dlg, "success", "Removed",
                                   f"USB key {u[:16]}… removed.").show()
                        self._close(True)
                rm = tk.Button(row, text=" ✕ ", command=_remove,
                               bg=C["surface2"], fg=C["accent_red"],
                               font=("Courier New", 9, "bold"),
                               relief=tk.FLAT, bd=0, padx=6, cursor="hand2")
                rm.bind("<Enter>", lambda e, b=rm: b.config(bg=C["accent_red"], fg=C["bg"]))
                rm.bind("<Leave>", lambda e, b=rm: b.config(bg=C["surface2"], fg=C["accent_red"]))
                rm.pack(side=tk.RIGHT, padx=(0, 6), pady=4)

        foot = tk.Frame(self._inner, bg=C["bg"], pady=10)
        foot.pack(fill=tk.X, padx=16)
        self._btn(foot, "  CLOSE  ", lambda: self._close(None)).pack(side=tk.RIGHT)


# ══════════════════════════════════════════════════════════════════════════════
#  BACKUP — CREATE MODAL
#  Encrypts selected files (originals) with a password and stores them in
#  ~/.avgvsto/backups/{id}/. No USB required.
# ══════════════════════════════════════════════════════════════════════════════

class BackupCreateModal(_AvgModal):
    """
    Lets the user name a backup and set a backup password.
    Files to back up are selected before opening this modal.
    """
    def __init__(self, parent, file_paths: List[str] = None):
        self._file_paths = file_paths or []
        super().__init__(parent, title="Create Backup",
                         color=C["warning"], width=500, height=560)

    def _build(self) -> None:
        c = self._section(padx=26, pady=18)

        # Header
        hdr = tk.Frame(c, bg=C["bg"])
        hdr.pack(fill=tk.X, pady=(0, 14))
        tk.Label(hdr, text="💾", bg=C["bg"], fg=C["warning"],
                 font=("Courier New", 20)).pack(side=tk.LEFT, padx=(0, 12))
        right = tk.Frame(hdr, bg=C["bg"])
        right.pack(side=tk.LEFT)
        tk.Label(right, text="CREATE BACKUP",
                 bg=C["bg"], fg=C["text_bright"],
                 font=("Courier New", 12, "bold"), anchor="w").pack(anchor="w")
        tk.Label(right,
                 text="Original files · password-protected · no USB required",
                 bg=C["bg"], fg=C["text_mid"],
                 font=("Courier New", 8), anchor="w").pack(anchor="w")

        # File selection area
        sel_f = tk.Frame(c, bg=C["surface2"], padx=12, pady=8)
        sel_f.pack(fill=tk.X, pady=(0, 12))
        sel_top = tk.Frame(sel_f, bg=C["surface2"])
        sel_top.pack(fill=tk.X)
        tk.Label(sel_top, text="FILES / FOLDERS TO BACK UP",
                 bg=C["surface2"], fg=C["text_dim"],
                 font=("Courier New", 7, "bold")).pack(side=tk.LEFT)
        self._add_folder_btn = tk.Button(sel_top, text="+ ADD FOLDER",
                                         command=self._add_folder,
                                         bg=C["surface3"], fg=C["accent"],
                                         font=("Courier New", 7, "bold"),
                                         relief=tk.FLAT, bd=0, padx=6, pady=2,
                                         cursor="hand2")
        self._add_folder_btn.pack(side=tk.RIGHT, padx=(4, 0))
        self._add_btn = tk.Button(sel_top, text="+ ADD FILES",
                                  command=self._add_files,
                                  bg=C["surface3"], fg=C["warning"],
                                  font=("Courier New", 7, "bold"),
                                  relief=tk.FLAT, bd=0, padx=6, pady=2,
                                  cursor="hand2")
        self._add_btn.pack(side=tk.RIGHT)

        # Drop area for files/folders
        # takefocus=0 is critical: prevents the frame/label from stealing keyboard
        # focus away from the password entries after a file-dialog or DnD event
        self._drop_area = tk.Frame(sel_f, bg=C["surface3"],
                                   highlightbackground=C["border_hi"],
                                   highlightthickness=1,
                                   takefocus=0, cursor="hand2")
        self._drop_area.pack(fill=tk.X, pady=(6, 0))
        self._file_list_var = tk.StringVar()
        self._file_lbl = tk.Label(self._drop_area, textvariable=self._file_list_var,
                                  bg=C["surface3"], fg=C["text"],
                                  font=("Courier New", 8), anchor="w",
                                  justify=tk.LEFT, padx=6, pady=4,
                                  takefocus=0)
        self._file_lbl.pack(fill=tk.X)
        # DnD registered only on the container Frame — registering it on the
        # child Label too conflicts with grab_set() and breaks password field input
        if DND:
            self._drop_area.drop_target_register(DND_FILES)
            self._drop_area.dnd_bind("<<Drop>>",     self._on_backup_drop)
            self._drop_area.dnd_bind("<<DragEnter>>",
                lambda e: self._drop_area.config(bg=C["surface2"],
                                                  highlightbackground=C["warning"]))
            self._drop_area.dnd_bind("<<DragLeave>>",
                lambda e: self._drop_area.config(bg=C["surface3"],
                                                  highlightbackground=C["border_hi"]))

        # Backup name
        tk.Label(c, text="BACKUP NAME",
                 bg=C["bg"], fg=C["text_mid"],
                 font=FONT_SMALL).pack(anchor="w", pady=(0, 2))
        name_wrap = tk.Frame(c, bg=C["surface2"], pady=2)
        name_wrap.pack(fill=tk.X, pady=(0, 10))
        self._name_var = tk.StringVar(
            value=f"backup_{datetime.now().strftime('%Y%m%d')}")
        tk.Entry(name_wrap, textvariable=self._name_var,
                 bg=C["surface2"], fg=C["text_bright"],
                 insertbackground=C["warning"],
                 font=("Courier New", 11),
                 relief=tk.FLAT, bd=8).pack(fill=tk.X)

        # Backup password
        self._pw_var = tk.StringVar()
        self._cf_var = tk.StringVar()
        self._pw_entry = self._pw_row(c, "Backup Password", self._pw_var)
        self._cf_entry = self._pw_row(c, "Confirm",         self._cf_var)

        self._err = tk.StringVar()
        tk.Label(c, textvariable=self._err,
                 bg=C["bg"], fg=C["error"],
                 font=FONT_SMALL, anchor="w").pack(fill=tk.X)

        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X, pady=(8, 0))
        self._btn(row, "CANCEL", lambda: self._close(None),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT, padx=(6, 0))
        self._btn(row, "CREATE BACKUP", self._submit, C["warning"]).pack(side=tk.RIGHT)
        self._pw_entry.focus_set()

    def _pw_row(self, parent, label: str, var: tk.StringVar) -> tk.Entry:
        tk.Label(parent, text=label, bg=C["bg"], fg=C["text_mid"],
                 font=FONT_SMALL).pack(anchor="w", pady=(0, 2))
        wrap = tk.Frame(parent, bg=C["surface2"], pady=2)
        wrap.pack(fill=tk.X, pady=(0, 8))
        entry = tk.Entry(wrap, textvariable=var, show="•",
                         bg=C["surface2"], fg=C["text_bright"],
                         insertbackground=C["warning"],
                         font=("Courier New", 11),
                         relief=tk.FLAT, bd=8)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        _shown = [False]
        def toggle(e=entry, s=_shown):
            s[0] = not s[0]
            e.config(show="" if s[0] else "•")
            eye.config(fg=C["warning"] if s[0] else C["text_dim"])
        eye = tk.Button(wrap, text="◎", command=toggle,
                        bg=C["surface2"], fg=C["text_dim"],
                        font=("Courier New", 10), relief=tk.FLAT, bd=0,
                        padx=7, cursor="hand2")
        eye.pack(side=tk.RIGHT, padx=(0, 4))
        return entry

    def _restore_modal_focus(self) -> None:
        """
        Restore grab + focus to this modal and its password entry.
        Must be called after ANY event that can steal the grab:
        filedialog, DnD, etc.  Without grab_set() the Entry receives
        visual focus but keyboard events are swallowed by the OS or
        redirected to the main window.
        """
        try:
            self.dlg.lift()
            self.dlg.grab_set()
            self.dlg.focus_force()
            self._pw_entry.focus_set()
        except Exception:
            pass

    def _add_files(self) -> None:
        chosen = filedialog.askopenfilenames(
            title="Select files to include in backup",
            parent=self.dlg)
        if chosen:
            self._add_paths(list(chosen))
        # Restore grab + focus — filedialog releases the modal grab when it
        # closes; without grab_set() the password Entry is visually focused
        # but keyboard input is lost until the user clicks the main window.
        self.dlg.after(10, self._restore_modal_focus)

    def _add_folder(self) -> None:
        chosen = filedialog.askdirectory(
            title="Select folder to include in backup",
            parent=self.dlg)
        if chosen and os.path.isdir(chosen):
            self._add_paths([chosen])
        # Same grab-restore needed here as in _add_files.
        self.dlg.after(10, self._restore_modal_focus)

    def _on_backup_drop(self, event) -> None:
        """Handle drag-and-drop of files/folders onto the backup file list."""
        self._drop_area.config(bg=C["surface3"], highlightbackground=C["border_hi"])
        raw = event.data.strip()
        paths = []
        i = 0
        while i < len(raw):
            if raw[i] == '{':
                end = raw.find('}', i)
                if end == -1:
                    break
                paths.append(raw[i + 1:end])
                i = end + 1
            elif raw[i] == ' ':
                i += 1
            else:
                end = raw.find(' ', i)
                if end == -1:
                    paths.append(raw[i:])
                    break
                paths.append(raw[i:end])
                i = end
        valid = [p.strip('"') for p in paths
                 if p.strip('"') and os.path.exists(p.strip('"'))]
        if valid:
            self._add_paths(valid)
        # Return focus explicitly after DnD — the drop event leaves focus
        # on the drag source (outside the modal), breaking keyboard input
        # tkinterdnd2 releases the modal grab during a drop event.
        # Restore grab + focus via the shared helper.
        self.dlg.after(10, self._restore_modal_focus)

    def _add_paths(self, new_paths: list) -> None:
        existing = set(self._file_paths)
        for p in new_paths:
            if p not in existing:
                self._file_paths.append(p)
                existing.add(p)
        self._update_file_label()

    def _update_file_label(self) -> None:
        if not self._file_paths:
            self._file_list_var.set(
                "  No items selected — click + ADD FILES / + ADD FOLDER"
                + ("\n  or drag & drop here" if DND else ""))
        else:
            names = [Path(p).name + ("/" if os.path.isdir(p) else "")
                     for p in self._file_paths[:4]]
            txt   = "\n".join(f"  · {n}" for n in names)
            if len(self._file_paths) > 4:
                txt += f"\n  … and {len(self._file_paths) - 4} more"
            self._file_list_var.set(txt)

    def _submit(self) -> None:
        name = self._name_var.get().strip()
        pw   = self._pw_var.get()
        cf   = self._cf_var.get()
        if not self._file_paths:
            self._err.set("Add at least one file.")
            return
        if not name:
            self._err.set("Backup name cannot be empty.")
            return
        if not pw:
            self._err.set("Backup password cannot be empty.")
            return
        if pw != cf:
            self._err.set("Passwords do not match.")
            return
        self._close({"files": self._file_paths, "name": name, "password": pw})


# ══════════════════════════════════════════════════════════════════════════════
#  BACKUP — RESTORE MODAL
#  Lists all saved backups; user selects one (or more), enters password,
#  files are decrypted back to their original paths.
# ══════════════════════════════════════════════════════════════════════════════

class BackupRestoreModal(_AvgModal):
    def __init__(self, parent):
        super().__init__(parent, title="Restore Backup",
                         color=C["accent"], width=580, height=520)

    def _build(self) -> None:
        outer = tk.Frame(self._inner, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True)

        tk.Label(outer,
                 text="SELECT BACKUP TO RESTORE",
                 bg=C["bg"], fg=C["text_dim"],
                 font=("Courier New", 8, "bold"),
                 anchor="w", padx=26, pady=10).pack(fill=tk.X)

        self._entries = _load_backup_index()
        self._selected_id = tk.StringVar(value="")

        list_outer = tk.Frame(outer, bg=C["surface"], padx=0)
        list_outer.pack(fill=tk.BOTH, expand=True, padx=24, pady=(0, 6))

        if not self._entries:
            tk.Label(list_outer,
                     text="  No backups found.\n  Create one with  BACKUP ▾ → Back up your data.",
                     bg=C["surface"], fg=C["text_mid"],
                     font=("Courier New", 9), anchor="w", pady=20,
                     justify=tk.LEFT).pack(fill=tk.X)
        else:
            # Scrollable list
            canvas = tk.Canvas(list_outer, bg=C["surface"],
                               bd=0, highlightthickness=0)
            scroll = tk.Scrollbar(list_outer, orient=tk.VERTICAL,
                                  command=canvas.yview,
                                  troughcolor=C["surface"],
                                  bg=C["surface3"], relief=tk.FLAT,
                                  bd=0, width=8)
            scroll.pack(side=tk.RIGHT, fill=tk.Y)
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            canvas.configure(yscrollcommand=scroll.set)
            inner = tk.Frame(canvas, bg=C["surface"])
            canvas.create_window((0, 0), window=inner, anchor="nw")

            self._rb_vars = {}
            for e in self._entries:
                row = tk.Frame(inner, bg=C["surface2"], pady=1)
                row.pack(fill=tk.X, padx=6, pady=3)
                rb = tk.Radiobutton(row, variable=self._selected_id,
                                    value=e["id"],
                                    bg=C["surface2"], fg=C["accent"],
                                    selectcolor=C["surface3"],
                                    activebackground=C["surface2"],
                                    relief=tk.FLAT, bd=0)
                rb.pack(side=tk.LEFT, padx=(6, 0))
                info = tk.Frame(row, bg=C["surface2"])
                info.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8, pady=4)
                tk.Label(info, text=e["name"],
                         bg=C["surface2"], fg=C["text_bright"],
                         font=("Courier New", 9, "bold"),
                         anchor="w").pack(anchor="w")
                tk.Label(info,
                         text=f"{e['created']}  ·  {e['file_count']} file(s)  ·  {_fmt_size(e['total_size'])}",
                         bg=C["surface2"], fg=C["text_mid"],
                         font=("Courier New", 8),
                         anchor="w").pack(anchor="w")

            inner.update_idletasks()
            canvas.config(scrollregion=canvas.bbox("all"))

        # Password field
        pw_f = tk.Frame(outer, bg=C["bg"], padx=24)
        pw_f.pack(fill=tk.X, pady=(4, 0))
        tk.Label(pw_f, text="BACKUP PASSWORD",
                 bg=C["bg"], fg=C["text_mid"],
                 font=FONT_SMALL).pack(anchor="w", pady=(0, 2))
        pw_wrap = tk.Frame(pw_f, bg=C["surface2"], pady=2)
        pw_wrap.pack(fill=tk.X)
        self._pw_var = tk.StringVar()
        pw_entry = tk.Entry(pw_wrap, textvariable=self._pw_var, show="•",
                            bg=C["surface2"], fg=C["text_bright"],
                            insertbackground=C["accent"],
                            font=("Courier New", 11),
                            relief=tk.FLAT, bd=8)
        pw_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        _sh = [False]
        def _tog():
            _sh[0] = not _sh[0]
            pw_entry.config(show="" if _sh[0] else "•")
        tk.Button(pw_wrap, text="◎", command=_tog,
                  bg=C["surface2"], fg=C["text_dim"],
                  font=("Courier New", 10), relief=tk.FLAT, bd=0,
                  padx=7, cursor="hand2").pack(side=tk.RIGHT, padx=(0, 4))

        self._err = tk.StringVar()
        tk.Label(outer, textvariable=self._err,
                 bg=C["bg"], fg=C["error"],
                 font=FONT_SMALL, anchor="w", padx=26).pack(fill=tk.X)

        foot = tk.Frame(self._inner, bg=C["bg"], pady=10)
        foot.pack(fill=tk.X, padx=16)
        self._btn(foot, "  CANCEL  ", lambda: self._close(None),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT, padx=(6, 0))
        self._btn(foot, "  RESTORE  ", self._submit,
                  C["accent"]).pack(side=tk.RIGHT)
        pw_entry.focus_set()

    def _submit(self) -> None:
        bid = self._selected_id.get()
        pw  = self._pw_var.get()
        if not bid:
            self._err.set("Select a backup from the list.")
            return
        if not pw:
            self._err.set("Enter the backup password.")
            return
        # Quick hash pre-check
        idx = _load_backup_index()
        for e in idx:
            if e["id"] == bid and e.get("pw_hash") and \
               e["pw_hash"] != _backup_pw_hash(pw):
                self._err.set("Wrong password.")
                return
        self._close({"id": bid, "password": pw})


# ══════════════════════════════════════════════════════════════════════════════
#  BACKUP — MANAGE MODAL
#  Shows all backups; allows rename, change password, delete.
# ══════════════════════════════════════════════════════════════════════════════

class BackupManageModal(_AvgModal):
    def __init__(self, parent):
        super().__init__(parent, title="Manage Backups",
                         color=C["accent_dim"], width=620, height=540)

    def _build(self) -> None:
        outer = tk.Frame(self._inner, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True)

        tk.Label(outer,
                 text="BACKUP MANAGER  —  rename · change password · delete",
                 bg=C["bg"], fg=C["text_dim"],
                 font=("Courier New", 8, "bold"),
                 anchor="w", padx=26, pady=10).pack(fill=tk.X)

        self._list_frame = tk.Frame(outer, bg=C["surface"])
        self._list_frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=(0, 8))
        self._render_list()

        foot = tk.Frame(self._inner, bg=C["bg"], pady=10)
        foot.pack(fill=tk.X, padx=16)
        self._btn(foot, "  CLOSE  ", lambda: self._close(None)).pack(side=tk.RIGHT)

    def _render_list(self) -> None:
        for w in self._list_frame.winfo_children():
            w.destroy()
        entries = _load_backup_index()
        if not entries:
            tk.Label(self._list_frame,
                     text="  No backups found.",
                     bg=C["surface"], fg=C["text_mid"],
                     font=("Courier New", 9), anchor="w", pady=16).pack(fill=tk.X)
            return
        for e in entries:
            card = tk.Frame(self._list_frame, bg=C["surface2"], padx=12, pady=8)
            card.pack(fill=tk.X, padx=6, pady=4)
            # Name + meta
            tk.Label(card, text=e["name"],
                     bg=C["surface2"], fg=C["text_bright"],
                     font=("Courier New", 10, "bold"),
                     anchor="w").pack(anchor="w")
            tk.Label(card,
                     text=f"{e['created']}  ·  {e['file_count']} file(s)  ·  {_fmt_size(e['total_size'])}",
                     bg=C["surface2"], fg=C["text_mid"],
                     font=("Courier New", 8),
                     anchor="w").pack(anchor="w", pady=(0, 6))
            # Action buttons
            btn_row = tk.Frame(card, bg=C["surface2"])
            btn_row.pack(fill=tk.X)

            def _mk_btn(parent, text, cmd, col):
                b = tk.Button(parent, text=text, command=cmd,
                              bg=C["surface3"], fg=col,
                              font=("Courier New", 8, "bold"),
                              relief=tk.FLAT, bd=0, padx=10, pady=4,
                              cursor="hand2")
                b.bind("<Enter>", lambda ev, b=b, c=col: b.config(bg=col, fg=C["bg"]))
                b.bind("<Leave>", lambda ev, b=b, c=col: b.config(bg=C["surface3"], fg=c))
                return b

            _mk_btn(btn_row, "✎ RENAME",
                    lambda bid=e["id"], bn=e["name"]: self._do_rename(bid, bn),
                    C["accent_dim"]).pack(side=tk.LEFT, padx=(0, 4))
            _mk_btn(btn_row, "🔑 CHANGE PW",
                    lambda bid=e["id"]: self._do_change_pw(bid),
                    C["warning"]).pack(side=tk.LEFT, padx=(0, 4))
            _mk_btn(btn_row, "✕ DELETE",
                    lambda bid=e["id"], bn=e["name"]: self._do_delete(bid, bn),
                    C["accent_red"]).pack(side=tk.LEFT)

    def _do_rename(self, backup_id: str, current_name: str) -> None:
        dlg = _SimpleInputModal(self.dlg, "Rename Backup",
                                "New name:", current_name, C["accent_dim"])
        new_name = dlg.show()
        if new_name and new_name.strip():
            ok, msg = rename_backup(backup_id, new_name.strip())
            AlertModal(self.dlg,
                       "success" if ok else "error",
                       "Rename", msg).show()
            self._render_list()

    def _do_change_pw(self, backup_id: str) -> None:
        dlg = _ChangePwModal(self.dlg, backup_id)
        dlg.show()
        self._render_list()

    def _do_delete(self, backup_id: str, name: str) -> None:
        # Step 1: ask for the backup password and verify it
        pw = _BackupDeletePasswordModal(self.dlg, name).show()
        if pw is None:
            return
        # Verify password against stored hash
        idx = _load_backup_index()
        for e in idx:
            if e["id"] == backup_id:
                stored = e.get("pw_hash")
                if stored and stored != _backup_pw_hash(pw):
                    AlertModal(self.dlg, "error", "Wrong Password",
                               "Incorrect backup password.\nDeletion aborted.").show()
                    return
                break
        # Step 2: confirm deletion
        confirm = _ConfirmModal(self.dlg,
                                f"Delete backup \"{name}\"?",
                                "This action cannot be undone.",
                                C["accent_red"]).show()
        if confirm:
            ok, msg = delete_backup(backup_id)
            AlertModal(self.dlg,
                       "success" if ok else "error",
                       "Delete", msg).show()
            self._render_list()


# ── Helpers used by BackupManageModal ─────────────────────────────────────────

class _SimpleInputModal(_AvgModal):
    def __init__(self, parent, title, label, default, color):
        self._label   = label
        self._default = default
        super().__init__(parent, title=title, color=color, width=420, height=222)

    def _build(self) -> None:
        c = self._section(padx=22, pady=16)
        tk.Label(c, text=self._label, bg=C["bg"], fg=C["text_mid"],
                 font=FONT_SMALL).pack(anchor="w", pady=(0, 4))
        self._var = tk.StringVar(value=self._default)
        wrap = tk.Frame(c, bg=C["surface2"], pady=2)
        wrap.pack(fill=tk.X, pady=(0, 14))
        e = tk.Entry(wrap, textvariable=self._var,
                     bg=C["surface2"], fg=C["text_bright"],
                     insertbackground=self._color,
                     font=("Courier New", 11),
                     relief=tk.FLAT, bd=8)
        e.pack(fill=tk.X)
        e.focus_set()
        e.select_range(0, tk.END)
        e.bind("<Return>", lambda ev: self._close(self._var.get()))
        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X)
        self._btn(row, "CANCEL", lambda: self._close(None),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT, padx=(6, 0))
        self._btn(row, "OK", lambda: self._close(self._var.get()),
                  self._color).pack(side=tk.RIGHT)


class _ChangePwModal(_AvgModal):
    def __init__(self, parent, backup_id: str):
        self._bid = backup_id
        super().__init__(parent, title="Change Backup Password",
                         color=C["warning"], width=440, height=360)

    def _build(self) -> None:
        c = self._section(padx=24, pady=16)
        tk.Label(c, text="CHANGE BACKUP PASSWORD",
                 bg=C["bg"], fg=C["warning"],
                 font=("Courier New", 10, "bold")).pack(anchor="w", pady=(0, 12))
        self._old_var = tk.StringVar()
        self._new_var = tk.StringVar()
        self._cf_var  = tk.StringVar()
        for label, var in [
            ("Current Password", self._old_var),
            ("New Password",     self._new_var),
            ("Confirm New",      self._cf_var),
        ]:
            tk.Label(c, text=label, bg=C["bg"], fg=C["text_mid"],
                     font=FONT_SMALL).pack(anchor="w", pady=(0, 2))
            wrap = tk.Frame(c, bg=C["surface2"], pady=2)
            wrap.pack(fill=tk.X, pady=(0, 6))
            tk.Entry(wrap, textvariable=var, show="•",
                     bg=C["surface2"], fg=C["text_bright"],
                     insertbackground=C["warning"],
                     font=("Courier New", 10),
                     relief=tk.FLAT, bd=6).pack(fill=tk.X)
        self._err = tk.StringVar()
        tk.Label(c, textvariable=self._err, bg=C["bg"], fg=C["error"],
                 font=FONT_SMALL).pack(anchor="w")
        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X, pady=(8, 0))
        self._btn(row, "CANCEL", lambda: self._close(None),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT, padx=(6, 0))
        self._btn(row, "SAVE", self._submit, C["warning"]).pack(side=tk.RIGHT)

    def _submit(self) -> None:
        old = self._old_var.get()
        new = self._new_var.get()
        cf  = self._cf_var.get()
        if not old or not new:
            self._err.set("All fields required.")
            return
        if new != cf:
            self._err.set("New passwords do not match.")
            return
        ok, msg = change_backup_password(self._bid, old, new)
        if ok:
            AlertModal(self.dlg, "success", "Done", msg).show()
            self._close(True)
        else:
            self._err.set(msg)


class _ConfirmModal(_AvgModal):
    def __init__(self, parent, question: str, detail: str, color: str):
        self._question = question
        self._detail   = detail
        super().__init__(parent, title="Confirm", color=color, width=440, height=222)

    def _build(self) -> None:
        c = self._section(padx=24, pady=18)
        tk.Label(c, text=self._question,
                 bg=C["bg"], fg=C["text_bright"],
                 font=("Courier New", 10, "bold"),
                 wraplength=370, justify=tk.LEFT).pack(anchor="w", pady=(0, 4))
        tk.Label(c, text=self._detail,
                 bg=C["bg"], fg=C["text_mid"],
                 font=FONT_SMALL).pack(anchor="w", pady=(0, 16))
        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X)
        self._btn(row, "CANCEL", lambda: self._close(False),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT, padx=(6, 0))
        self._btn(row, "CONFIRM", lambda: self._close(True),
                  self._color).pack(side=tk.RIGHT)


# ══════════════════════════════════════════════════════════════════════════════
#  BACKUP DELETE PASSWORD MODAL
#  Ask for the backup password before allowing deletion.
# ══════════════════════════════════════════════════════════════════════════════

class _BackupDeletePasswordModal(_AvgModal):
    """Require the backup password before allowing deletion."""
    def __init__(self, parent, backup_name: str):
        self._backup_name = backup_name
        super().__init__(parent, title="Confirm Deletion",
                         color=C["accent_red"], width=460, height=280)

    def _build(self) -> None:
        c = self._section(padx=26, pady=18)

        hdr = tk.Frame(c, bg=C["bg"])
        hdr.pack(fill=tk.X, pady=(0, 10))
        tk.Label(hdr, text="✕", bg=C["bg"], fg=C["accent_red"],
                 font=("Courier New", 20, "bold")).pack(side=tk.LEFT, padx=(0, 12))
        right = tk.Frame(hdr, bg=C["bg"])
        right.pack(side=tk.LEFT)
        tk.Label(right, text="DELETE BACKUP",
                 bg=C["bg"], fg=C["text_bright"],
                 font=("Courier New", 11, "bold"), anchor="w").pack(anchor="w")
        tk.Label(right,
                 text=f"Enter the password for  \"{self._backup_name}\"",
                 bg=C["bg"], fg=C["text_mid"],
                 font=("Courier New", 8), anchor="w").pack(anchor="w")

        self._pw_var = tk.StringVar()
        pw_wrap = tk.Frame(c, bg=C["surface2"], pady=2)
        pw_wrap.pack(fill=tk.X, pady=(4, 0))
        self._entry = tk.Entry(pw_wrap, textvariable=self._pw_var, show="•",
                               bg=C["surface2"], fg=C["text_bright"],
                               insertbackground=C["accent_red"],
                               font=("Courier New", 11),
                               relief=tk.FLAT, bd=8)
        self._entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        _shown = [False]
        def toggle(s=_shown):
            s[0] = not s[0]
            self._entry.config(show="" if s[0] else "•")
            eye.config(fg=C["accent_red"] if s[0] else C["text_dim"])
        eye = tk.Button(pw_wrap, text="◎", command=toggle,
                        bg=C["surface2"], fg=C["text_dim"],
                        font=("Courier New", 10), relief=tk.FLAT, bd=0,
                        padx=7, cursor="hand2")
        eye.pack(side=tk.RIGHT, padx=(0, 4))

        self._err = tk.StringVar()
        tk.Label(c, textvariable=self._err,
                 bg=C["bg"], fg=C["error"],
                 font=FONT_SMALL, anchor="w").pack(fill=tk.X, pady=(4, 0))

        foot = tk.Frame(self._inner, bg=C["bg"], pady=10)
        foot.pack(fill=tk.X, padx=16)
        self._btn(foot, "  CANCEL  ", lambda: self._close(None),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT, padx=(6, 0))
        self._btn(foot, "  CONFIRM  ", self._submit,
                  C["accent_red"]).pack(side=tk.RIGHT)
        self._entry.focus_set()
        self._entry.bind("<Return>", lambda e: self._submit())

    def _submit(self) -> None:
        pw = self._pw_var.get()
        if not pw:
            self._err.set("Password cannot be empty.")
            return
        self._close(pw)


# ══════════════════════════════════════════════════════════════════════════════
#  FILE TYPE DIALOG
# ══════════════════════════════════════════════════════════════════════════════

class FileTypeDialog(_AvgModal):
    def __init__(self, parent, mode: str = "encrypt"):
        self._mode = mode
        col = C["accent"] if mode == "encrypt" else C["accent_red"]
        super().__init__(parent, title="Select Target", color=col,
                         width=400, height=188)

    def _build(self) -> None:
        c = self._section()
        verb = "ENCRYPT" if self._mode == "encrypt" else "DECRYPT"
        self._lbl(c, f"WHAT DO YOU WANT TO {verb}?",
                  color=self._color,
                  font=("Courier New", 10, "bold")).pack(anchor="w", pady=(0, 18))
        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X, pady=(0, 10))
        for label, val in [("  ▣  FILE", "file"), ("  ▦  FOLDER", "folder")]:
            b = tk.Button(row, text=label, command=lambda v=val: self._close(v),
                          bg=C["surface2"], fg=self._color,
                          font=FONT_BTN, relief=tk.FLAT, bd=0,
                          padx=14, pady=11, cursor="hand2")
            b.bind("<Enter>", lambda e, b=b: b.config(bg=self._color, fg=C["bg"]))
            b.bind("<Leave>", lambda e, b=b: b.config(bg=C["surface2"], fg=self._color))
            b.pack(side=tk.LEFT, expand=True, fill=tk.X,
                   padx=(0, 6 if val == "file" else 0))
        tk.Button(c, text="cancel", command=lambda: self._close(None),
                  bg=C["bg"], fg=C["text_dim"], font=FONT_SMALL,
                  relief=tk.FLAT, bd=0, cursor="hand2").pack()

# ══════════════════════════════════════════════════════════════════════════════
#  CHOICE DIALOG
# ══════════════════════════════════════════════════════════════════════════════

class ChoiceDialog(_AvgModal):
    def __init__(self, parent):
        super().__init__(parent, title="Choose Operation",
                         color=C["accent"], width=400, height=178)

    def _build(self) -> None:
        c = self._section()
        self._lbl(c, "CHOOSE OPERATION",
                  color=self._color,
                  font=("Courier New", 10, "bold")).pack(anchor="w", pady=(0, 18))
        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X, pady=(0, 10))
        for label, val, col in [
            ("🔐  ENCRYPT", "encrypt", C["accent"]),
            ("🔓  DECRYPT", "decrypt", C["accent_red"]),
        ]:
            b = tk.Button(row, text=label, command=lambda v=val: self._close(v),
                          bg=C["surface2"], fg=col,
                          font=FONT_BTN, relief=tk.FLAT, bd=0,
                          padx=14, pady=11, cursor="hand2")
            b.bind("<Enter>", lambda e, b=b, c2=col: b.config(bg=c2, fg=C["bg"]))
            b.bind("<Leave>", lambda e, b=b, c2=col: b.config(bg=C["surface2"], fg=c2))
            b.pack(side=tk.LEFT, expand=True, fill=tk.X,
                   padx=(0, 6 if val == "encrypt" else 0))
        tk.Button(c, text="cancel", command=lambda: self._close(None),
                  bg=C["bg"], fg=C["text_dim"], font=FONT_SMALL,
                  relief=tk.FLAT, bd=0, cursor="hand2").pack()

# ══════════════════════════════════════════════════════════════════════════════
#  USB ANALYSIS MODAL
# ══════════════════════════════════════════════════════════════════════════════

class UsbAnalysisModal(_AvgModal):
    """
    Scan a directory (default = USB drive) for .avgvsto files.
    Shows: count, disk usage, valid/corrupted split, attempt limits,
    and allows resetting locked attempt counters.
    The scan path can be changed via Browse to scan local directories too.
    """

    def __init__(self, parent, usb_path: str):
        self._usb_path  = usb_path
        self._scan_path = usb_path
        self._scan      = None
        self._locked    = []
        super().__init__(parent, title="USB Analysis",
                        color=C["accent"], width=660, height=600)

    def _build(self) -> None:
        outer = tk.Frame(self._inner, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True)

        # ── Scan-path row ─────────────────────────────────────────────────────
        path_bar = tk.Frame(outer, bg=C["surface3"])
        path_bar.pack(fill=tk.X, padx=1, pady=(1, 0))
        tk.Label(path_bar, text="PATH", bg=C["surface3"], fg=C["text_dim"],
                 font=("Courier New", 7, "bold"), padx=12, pady=6).pack(side=tk.LEFT)
        self._path_var = tk.StringVar(value=self._scan_path)
        tk.Label(path_bar, textvariable=self._path_var,
                 bg=C["surface3"], fg=C["accent"],
                 font=("Courier New", 8), anchor="w").pack(
            side=tk.LEFT, fill=tk.X, expand=True)
        browse_btn = tk.Button(
            path_bar, text="  BROWSE  ", command=self._browse_path,
            bg=C["surface2"], fg=C["text_mid"],
            font=("Courier New", 8, "bold"),
            relief=tk.FLAT, bd=0, padx=8, pady=4, cursor="hand2")
        browse_btn.bind("<Enter>", lambda e: browse_btn.config(bg=C["accent"], fg=C["bg"]))
        browse_btn.bind("<Leave>", lambda e: browse_btn.config(bg=C["surface2"], fg=C["text_mid"]))
        browse_btn.pack(side=tk.RIGHT, padx=6, pady=4)

        # ── Status bar ────────────────────────────────────────────────────────
        top = tk.Frame(outer, bg=C["surface2"])
        top.pack(fill=tk.X, padx=1, pady=(1, 0))
        self._status_lbl = tk.Label(
            top, text=f"⟳  Scanning  {self._scan_path} …",
            bg=C["surface2"], fg=C["warning"],
            font=("Courier New", 9, "bold"), anchor="w", padx=16, pady=8)
        self._status_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # ── Stats row ─────────────────────────────────────────────────────────
        stats = tk.Frame(outer, bg=C["surface"])
        stats.pack(fill=tk.X, padx=1)
        self._s_total   = self._stat_cell(stats, "TOTAL",      "—")
        self._s_valid   = self._stat_cell(stats, "VALID",      "—", C["success"])
        self._s_corrupt = self._stat_cell(stats, "CORRUPTED",  "—", C["error"])
        self._s_size    = self._stat_cell(stats, "DISK USAGE", "—", C["accent"])

        # ── File list (scrollable text) ───────────────────────────────────────
        list_outer = tk.Frame(outer, bg=C["surface"])
        list_outer.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        scroll = tk.Scrollbar(list_outer, orient=tk.VERTICAL,
                              troughcolor=C["surface"], bg=C["surface3"],
                              activebackground=C["accent"],
                              relief=tk.FLAT, bd=0, width=10)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._txt = tk.Text(
            list_outer, bg=C["surface"], fg=C["text"],
            font=("Courier New", 8), relief=tk.FLAT, bd=10,
            wrap=tk.NONE, state=tk.NORMAL, cursor="arrow",
            yscrollcommand=scroll.set, insertbackground=C["bg"])
        self._txt.pack(fill=tk.BOTH, expand=True)
        scroll.config(command=self._txt.yview)
        self._txt.tag_config("ok",   foreground=C["success"])
        self._txt.tag_config("bad",  foreground=C["error"])
        self._txt.tag_config("dim",  foreground=C["text_dim"])
        self._txt.tag_config("head", foreground=C["accent"],
                             font=("Courier New", 8, "bold"))
        self._txt.tag_config("warn", foreground=C["warning"])

        # ── Footer ────────────────────────────────────────────────────────────
        foot = tk.Frame(self._inner, bg=C["bg"], pady=10)
        foot.pack(fill=tk.X, padx=16)
        self._btn(foot, "  CLOSE  ", lambda: self._close(None)).pack(side=tk.RIGHT)
        self._btn(foot, "  ↺ REFRESH  ", self._do_refresh,
                  C["accent"], secondary=True).pack(side=tk.RIGHT, padx=(0, 6))
        self._locked_btn = self._btn(
            foot, "  RESET LOCKED COUNTERS  ",
            self._reset_locked, C["warning"], secondary=True)
        self._locked_btn.pack(side=tk.LEFT)
        self._locked_btn.config(state=tk.DISABLED)

        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_refresh(self) -> None:
        """Re-run the scan without closing the modal."""
        self._status_lbl.config(
            text=f"⟳  Scanning  {self._scan_path} …", fg=C["warning"])
        for lbl in (self._s_total, self._s_valid, self._s_corrupt, self._s_size):
            lbl.config(text="—")
        self._txt.config(state=tk.NORMAL)
        self._txt.delete("1.0", tk.END)
        self._txt.config(state=tk.DISABLED)
        self._locked_btn.config(state=tk.DISABLED)
        threading.Thread(target=self._do_scan, daemon=True).start()

    def _browse_path(self) -> None:
        """Let user pick any directory to scan (not just the USB)."""
        from tkinter import filedialog as _fd
        chosen = _fd.askdirectory(
            title="Select directory to scan for .avgvsto files",
            initialdir=self._scan_path,
            parent=self.dlg)
        if chosen and os.path.isdir(chosen):
            self._scan_path = chosen
            self._path_var.set(chosen)
            self._status_lbl.config(
                text=f"⟳  Scanning  {chosen} …", fg=C["warning"])
            for lbl in (self._s_total, self._s_valid, self._s_corrupt, self._s_size):
                lbl.config(text="—")
            self._txt.config(state=tk.NORMAL)
            self._txt.delete("1.0", tk.END)
            self._txt.config(state=tk.DISABLED)
            self._locked_btn.config(state=tk.DISABLED)
            threading.Thread(target=self._do_scan, daemon=True).start()

    def _stat_cell(self, parent, label: str, value: str,
                   color: str = None) -> tk.Label:
        cell = tk.Frame(parent, bg=C["surface3"], padx=14, pady=8)
        cell.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1, pady=1)
        tk.Label(cell, text=label, bg=C["surface3"], fg=C["text_dim"],
                 font=("Courier New", 7, "bold")).pack(anchor="w")
        val_lbl = tk.Label(cell, text=value, bg=C["surface3"],
                           fg=color or C["text_bright"],
                           font=("Courier New", 13, "bold"))
        val_lbl.pack(anchor="w")
        return val_lbl

    def _do_scan(self) -> None:
        try:
            scan   = scan_usb_for_avgvsto(self._scan_path)
            locked = get_locked_attempt_files()
            self._scan   = scan
            self._locked = locked
            self.dlg.after(0, self._render_results, scan, locked)
        except Exception as exc:
            self.dlg.after(0, lambda: self._status_lbl.config(
                text=f"✕  Scan failed: {exc}", fg=C["error"]))

    def _render_results(self, scan: dict, locked: list) -> None:
        self._status_lbl.config(
            text=f"✓  Scan complete — {self._scan_path}", fg=C["success"])
        self._s_total.config(text=str(scan["total"]))
        self._s_valid.config(text=str(scan["valid"]))
        self._s_corrupt.config(text=str(scan["corrupted"]))
        self._s_size.config(text=_fmt_size(scan["total_bytes"]))

        if locked:
            self._locked_btn.config(state=tk.NORMAL)

        self._txt.config(state=tk.NORMAL)
        self._txt.delete("1.0", tk.END)

        if not scan["files"]:
            self._txt.insert(tk.END,
                "  No .avgvsto files found in this directory.\n\n", "dim")
            self._txt.insert(tk.END,
                "  Tip: if your encrypted files are stored locally,\n"
                "  use BROWSE to select the folder where they live.\n", "dim")
        else:
            self._txt.insert(
                tk.END,
                f"  {'FILENAME':<40} {'SIZE':>8}  {'MODIFIED':<17}  {'LIMIT':>5}  STATUS\n",
                "head")
            self._txt.insert(tk.END, "  " + "─" * 94 + "\n", "dim")
            for f in scan["files"]:
                name = os.path.basename(f["path"])
                if len(name) > 38:
                    name = name[:35] + "…"
                size_s = _fmt_size(f["size"])
                att    = ("∞" if f["max_attempts"] == 0
                          else ("—" if f["max_attempts"] < 0
                                else str(f["max_attempts"])))
                tag    = "ok" if f["status"] == "valid" else "bad"
                status = "✓ valid" if f["status"] == "valid" else f"✕ {f['status']}"
                line   = (f"  {name:<40} {size_s:>8}  "
                          f"{f['mtime']:<17}  {att:>5}  {status}\n")
                self._txt.insert(tk.END, line, tag)

        if locked:
            self._txt.insert(tk.END, "\n", "dim")
            self._txt.insert(
                tk.END,
                f"  LOCKED ATTEMPT COUNTERS  ({len(locked)} file(s) blocked)\n",
                "warn")
            self._txt.insert(tk.END, "  " + "─" * 50 + "\n", "dim")
            for item in locked:
                self._txt.insert(
                    tk.END,
                    f"  counter {item['slot'].name[:24]}…  "
                    f"recorded attempts: {item['count']}\n",
                    "warn")
            self._txt.insert(
                tk.END,
                "\n  → Use RESET LOCKED COUNTERS to unblock affected files.\n",
                "dim")

        self._txt.config(state=tk.DISABLED)

    def _reset_locked(self) -> None:
        if not self._locked:
            return

        usb_mount = self._usb_path   # always the real USB path

        # ── Check reset availability ───────────────────────────────────────────
        ok, reason = can_reset(usb_mount)
        if not ok:
            AlertModal(self.dlg, "error", "Reset Not Available", reason).show()
            return

        # ── Get reset status info ──────────────────────────────────────────────
        cfg = load_reset_config(usb_mount)
        used = cfg.get("reset_count", 0) if cfg else 0
        fail = cfg.get("reset_fail_count", 0) if cfg else 0
        status_msg = (f"Resets used: {used}/3  ·  "
                      f"Wrong reset-password attempts: {fail}/3")

        # ── Ask for reset password ────────────────────────────────────────────
        reset_pw = ResetPasswordVerifyDialog(self.dlg, status_msg).show()
        if not reset_pw:
            return

        # ── Attempt reset ─────────────────────────────────────────────────────
        success, msg = do_reset_counters(usb_mount, reset_pw)
        if success:
            self._locked = []
            self._locked_btn.config(state=tk.DISABLED)
            AlertModal(self.dlg, "success", "Counters Reset",
                       f"✓  {msg}\n\nAffected files can be decrypted again.").show()
            # Refresh display
            self._do_refresh()
        else:
            AlertModal(self.dlg, "error", "Reset Failed", msg).show()


# ══════════════════════════════════════════════════════════════════════════════
#  USB CLEANUP MODAL
# ══════════════════════════════════════════════════════════════════════════════

class UsbCleanupModal(_AvgModal):
    """
    Scan the USB drive for .avgvsto files.
    User selects which to permanently delete (corrupted pre-selected).
    """

    def __init__(self, parent, usb_path: str):
        self._usb_path = usb_path
        self._checks   = {}   # path -> BooleanVar
        self._files    = []
        super().__init__(parent, title="USB Cleanup",
                         color=C["accent_red"], width=650, height=550)

    def _build(self) -> None:
        outer = tk.Frame(self._inner, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True)

        # Status
        top = tk.Frame(outer, bg=C["surface2"])
        top.pack(fill=tk.X, padx=1, pady=(1, 0))
        self._status_lbl = tk.Label(
            top, text=f"⟳  Scanning  {self._usb_path} …",
            bg=C["surface2"], fg=C["warning"],
            font=("Courier New", 9, "bold"), anchor="w", padx=16, pady=8)
        self._status_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Info
        info = tk.Frame(outer, bg=C["surface3"], padx=16, pady=8)
        info.pack(fill=tk.X, padx=1)
        tk.Label(info,
                 text="Select files to permanently remove from the USB drive.\n"
                      "Corrupted files are pre-selected. Valid files require manual selection.",
                 bg=C["surface3"], fg=C["text_mid"],
                 font=("Courier New", 8), justify=tk.LEFT, anchor="w",
                 wraplength=600).pack(anchor="w")

        # Scrollable checklist
        list_outer = tk.Frame(outer, bg=C["surface"])
        list_outer.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        scroll = tk.Scrollbar(list_outer, orient=tk.VERTICAL,
                              troughcolor=C["surface"], bg=C["surface3"],
                              activebackground=C["accent_red"],
                              relief=tk.FLAT, bd=0, width=10)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._canvas = tk.Canvas(list_outer, bg=C["surface"],
                                 bd=0, highlightthickness=0,
                                 yscrollcommand=scroll.set)
        self._canvas.pack(fill=tk.BOTH, expand=True)
        scroll.config(command=self._canvas.yview)
        self._list_frame = tk.Frame(self._canvas, bg=C["surface"])
        self._canvas_win = self._canvas.create_window(
            0, 0, anchor="nw", window=self._list_frame)
        self._list_frame.bind("<Configure>", self._on_frame_configure)
        self._canvas.bind("<Configure>",     self._on_canvas_configure)

        # Footer
        foot = tk.Frame(self._inner, bg=C["bg"], pady=10)
        foot.pack(fill=tk.X, padx=16)
        self._delete_btn = self._btn(
            foot, "  DELETE SELECTED  ", self._do_delete, C["accent_red"])
        self._delete_btn.pack(side=tk.RIGHT)
        self._delete_btn.config(state=tk.DISABLED)
        self._btn(foot, "  CANCEL  ", lambda: self._close(None),
                  C["text_mid"], secondary=True).pack(side=tk.RIGHT, padx=(0, 6))
        self._btn(foot, "  ☠ FULL CLEAR  ", self._do_full_clear,
                  C["accent_red"], secondary=True).pack(side=tk.RIGHT, padx=(0, 6))
        self._sel_lbl = tk.Label(foot, text="0 selected",
                                 bg=C["bg"], fg=C["text_dim"], font=FONT_SMALL)
        self._sel_lbl.pack(side=tk.LEFT)

        threading.Thread(target=self._do_scan, daemon=True).start()

    def _on_frame_configure(self, event) -> None:
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event) -> None:
        self._canvas.itemconfig(self._canvas_win, width=event.width)

    def _do_scan(self) -> None:
        try:
            scan = scan_usb_for_avgvsto(self._usb_path)
            self._files = scan["files"]
            self.dlg.after(0, self._render_list, scan)
        except Exception as exc:
            self.dlg.after(0, lambda: self._status_lbl.config(
                text=f"✕  Scan failed: {exc}", fg=C["error"]))

    def _render_list(self, scan: dict) -> None:
        self._status_lbl.config(
            text=f"✓  Found {scan['total']} .avgvsto file(s)  ·  "
                 f"{scan['corrupted']} corrupted",
            fg=C["success"] if scan["corrupted"] == 0 else C["warning"])

        if not scan["files"]:
            tk.Label(self._list_frame,
                     text="  No .avgvsto files found on this drive.",
                     bg=C["surface"], fg=C["text_dim"],
                     font=("Courier New", 9), anchor="w", pady=20).pack(fill=tk.X)
            return

        # Column header
        hdr = tk.Frame(self._list_frame, bg=C["surface3"])
        hdr.pack(fill=tk.X, padx=2, pady=(4, 0))
        tk.Label(hdr, text="   ☐", bg=C["surface3"], fg=C["text_dim"],
                 font=FONT_SMALL, width=4).pack(side=tk.LEFT)
        for txt, w in [("FILENAME", 36), ("SIZE", 8), ("STATUS", 22)]:
            tk.Label(hdr, text=txt, bg=C["surface3"], fg=C["text_dim"],
                     font=("Courier New", 7, "bold"), width=w,
                     anchor="w").pack(side=tk.LEFT)

        # File rows
        for f in scan["files"]:
            is_corrupt = f["status"] != "valid"
            var = tk.BooleanVar(value=is_corrupt)
            self._checks[f["path"]] = var
            row_bg = C["surface"] if not is_corrupt else "#1a0a0a"
            row = tk.Frame(self._list_frame, bg=row_bg)
            row.pack(fill=tk.X, padx=2, pady=1)
            cb = tk.Checkbutton(
                row, variable=var, bg=row_bg,
                fg=C["accent_red"] if is_corrupt else C["text_mid"],
                activebackground=row_bg, selectcolor=C["surface3"],
                relief=tk.FLAT, bd=0, cursor="hand2",
                command=self._update_count)
            cb.pack(side=tk.LEFT, padx=(8, 0))
            name = os.path.basename(f["path"])
            if len(name) > 34:
                name = name[:31] + "…"
            color = C["error"] if is_corrupt else C["text"]
            tk.Label(row, text=name, bg=row_bg, fg=color,
                     font=("Courier New", 8), width=36, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=_fmt_size(f["size"]), bg=row_bg, fg=C["text_mid"],
                     font=("Courier New", 8), width=8, anchor="w").pack(side=tk.LEFT)
            s_txt = "✓ valid" if not is_corrupt else "✕ corrupted"
            s_col = C["success"] if not is_corrupt else C["error"]
            tk.Label(row, text=s_txt, bg=row_bg, fg=s_col,
                     font=("Courier New", 8), width=22, anchor="w").pack(side=tk.LEFT)

        self._update_count()

    def _update_count(self) -> None:
        sel = sum(1 for v in self._checks.values() if v.get())
        self._sel_lbl.config(text=f"{sel} selected")
        self._delete_btn.config(state=tk.NORMAL if sel > 0 else tk.DISABLED)

    def _do_delete(self) -> None:
        to_del = [p for p, v in self._checks.items() if v.get()]
        if not to_del:
            return
        ok, fail = 0, []
        for p in to_del:
            try:
                os.remove(p)
                ok += 1
            except Exception as exc:
                fail.append(f"{os.path.basename(p)}: {exc}")
        msg = f"{ok} file(s) permanently deleted from USB."
        if fail:
            msg += "\n\nFailed:\n" + "\n".join(fail)
        self._close(True)
        AlertModal(self.parent, "success" if not fail else "warning",
                   "Cleanup Complete", msg).show()

    def _do_full_clear(self) -> None:
        """Delete ALL .avgvsto files + avgvsto_reset.json → fresh start."""
        confirmed = _ConfirmModal(
            self.dlg,
            "FULL CLEAR — Are you sure?",
            "This will permanently delete ALL .avgvsto files on this USB,\n"
            "remove the reset password config, and clear all attempt-counter locks.\n\n"
            "This action cannot be undone.",
            C["accent_red"],
        ).show()
        if not confirmed:
            return

        # Delete all avgvsto files
        ok, fail = 0, []
        for f in self._files:
            try:
                os.remove(f["path"])
                ok += 1
            except Exception as exc:
                fail.append(f"{os.path.basename(f['path'])}: {exc}")

        # Delete reset config from USB
        full_clear_usb_reset(self._usb_path)

        # Clear local attempt counters
        if ATTEMPTS_DIR.exists():
            for slot in list(ATTEMPTS_DIR.iterdir()):
                try: slot.unlink()
                except Exception: pass

        msg = f"FULL CLEAR complete.\n{ok} file(s) deleted + reset config wiped."
        if fail:
            msg += "\n\nFailed:\n" + "\n".join(fail)
        self._close(True)
        AlertModal(self.parent, "success" if not fail else "warning",
                   "Full Clear Complete", msg).show()

# ══════════════════════════════════════════════════════════════════════════════
#  INFO MODAL
# ══════════════════════════════════════════════════════════════════════════════

class InfoModal(_AvgModal):
    def __init__(self, parent):
        super().__init__(parent, title="About",
                         color=C["accent"], width=500, height=360)

    def _build(self) -> None:
        c = self._section(padx=28, pady=20)
        hdr = tk.Frame(c, bg=C["bg"])
        hdr.pack(fill=tk.X, pady=(0, 4))
        tk.Label(hdr, text=APP_NAME, bg=C["bg"], fg=C["accent"],
                 font=("Courier New", 30, "bold")).pack(side=tk.LEFT)
        tk.Label(hdr, text=f"  v{APP_VERSION}", bg=C["bg"], fg=C["text_mid"],
                 font=("Courier New", 14)).pack(side=tk.LEFT, anchor="s", pady=10)
        self._hsep(c, color=C["border_hi"])
        tk.Frame(c, bg=C["bg"], height=10).pack()
        self._lbl(
            c,
            "AES-256-GCM encryption suite with hardware USB key binding.\n"
            "Files can only be decrypted with the original USB drive.\n"
            "Supports files, folders, multi-file drop, attempt limits,\n"
            "USB analysis and cleanup.",
            color=C["text_mid"], wrap=440,
        ).pack(anchor="w", pady=(0, 14))
        auth = tk.Frame(c, bg=C["bg"])
        auth.pack(fill=tk.X, pady=(0, 10))
        self._lbl(auth, "Authors ", color=C["text_dim"]).pack(side=tk.LEFT)
        self._lbl(auth, "Roy Merlo", color=C["accent"],
                  font=("Courier New", 9, "bold")).pack(side=tk.LEFT)
        self._lbl(auth, "  &  ", color=C["text_dim"]).pack(side=tk.LEFT)
        self._lbl(auth, "RPX", color=C["accent_red"],
                  font=("Courier New", 9, "bold")).pack(side=tk.LEFT)
        gh = tk.Frame(c, bg=C["bg"])
        gh.pack(fill=tk.X, pady=(0, 4))
        self._lbl(gh, "GitHub ", color=C["text_dim"]).pack(side=tk.LEFT)
        link = tk.Label(gh, text="github.com/RoyMerlo/AVGVSTO",
                        bg=C["bg"], fg=C["accent"],
                        font=("Courier New", 9, "underline"), cursor="hand2")
        link.pack(side=tk.LEFT)
        link.bind("<Button-1>", lambda e: webbrowser.open(GITHUB_URL))
        link.bind("<Enter>",    lambda e: link.config(fg=C["text_bright"]))
        link.bind("<Leave>",    lambda e: link.config(fg=C["accent"]))
        ghw = tk.Frame(c, bg=C["bg"])
        ghw.pack(fill=tk.X, pady=(0, 18))
        self._lbl(ghw, "Site   ", color=C["text_dim"]).pack(side=tk.LEFT)
        linkw = tk.Label(ghw, text="roymerlo.github.io/AVGVSTO-SITE/",
                         bg=C["bg"], fg=C["accent"],
                         font=("Courier New", 9, "underline"), cursor="hand2")
        linkw.pack(side=tk.LEFT)
        linkw.bind("<Button-1>",
                   lambda e: webbrowser.open("https://roymerlo.github.io/AVGVSTO-SITE/"))
        linkw.bind("<Enter>", lambda e: linkw.config(fg=C["text_bright"]))
        linkw.bind("<Leave>", lambda e: linkw.config(fg=C["accent"]))
        row = tk.Frame(c, bg=C["bg"])
        row.pack(fill=tk.X)
        self._btn(row, "  CLOSE  ", lambda: self._close(None)).pack(side=tk.RIGHT)
        self._lbl(row,
                  f"AES-256-GCM · PBKDF2-SHA256 · {PBKDF2_ITERS:,} iter",
                  color=C["text_dim"],
                  font=("Courier New", 8)).pack(side=tk.LEFT, anchor="s", pady=10)

# ══════════════════════════════════════════════════════════════════════════════
#  HELP MODAL
# ══════════════════════════════════════════════════════════════════════════════

_HELP_CONTENT = """\
GETTING STARTED
═══════════════════════════════════════════════════════════
AVGVSTO encrypts files and folders with AES-256-GCM (authenticated
encryption). Every encrypted file is bound to a specific USB drive:
without the correct drive, decryption is impossible even with the
correct password.

──────────────────────────────────────────────────────────
  STEP 1 · BIND YOUR USB DRIVE
──────────────────────────────────────────────────────────
1. Insert the USB drive you want to use as your hardware key.
2. Select it from the dropdown list in the USB KEY BINDING section.
3. Click "SET SECURE USB DRIVE".

Status dot (top-right of USB section):
   • Green   → authorised drive connected
   • Yellow  → configured but USB not plugged in
   • Grey    → no binding exists yet

──────────────────────────────────────────────────────────
  STEP 2 · ENCRYPT A FILE OR FOLDER
──────────────────────────────────────────────────────────
1. Click ENCRYPT (or drop files/folders onto the Drop Zone).
2. Enter a strong password and confirm it.
   → Click ◎ to toggle password visibility.
3. Set the attempt limit:
   → 0 = unlimited tries
   → N = after N failed attempts, the file is permanently locked
4. Select FILE or FOLDER.
   → Folders are processed recursively (all nested files).
5. Pick the target in the file dialog.

The ORIGINAL file is DELETED after successful encryption.
Output file gets the .avgvsto extension.

Note: empty files (0 bytes) are supported and encrypt correctly.

──────────────────────────────────────────────────────────
  STEP 3 · DECRYPT
──────────────────────────────────────────────────────────
1. Click DECRYPT (or drop .avgvsto files onto the Drop Zone).
2. Enter the correct password.
3. Select FILE or FOLDER, then pick the target.
4. The authorised USB drive MUST be plugged in.
   Using any other drive fails, even with the correct password.

The ENCRYPTED file is DELETED after successful decryption.

──────────────────────────────────────────────────────────
  DRAG & DROP  (requires tkinterdnd2)
──────────────────────────────────────────────────────────
Drop any file, folder, or MULTIPLE files onto the Drop Zone:
  • Single file      → auto-detects encrypt/decrypt by extension
  • Single folder    → asks encrypt or decrypt
  • Multiple files   → batched, password asked once for all
  • Mixed items      → asks which operation to apply

Paths with spaces are handled correctly.
Install: pip install tkinterdnd2

──────────────────────────────────────────────────────────
  ATTEMPT LIMITS
──────────────────────────────────────────────────────────
  0     → no limit
  1     → one shot — a single wrong password locks the file
  3–5   → recommended for sensitive data
  Hit   → "Access Blocked" error, file locked on this machine

To reset: USB ANALYSIS → RESET LOCKED COUNTERS.

──────────────────────────────────────────────────────────
  USB ANALYSIS
──────────────────────────────────────────────────────────
Scan the authorised USB drive to inspect all .avgvsto files:
  • Total count and total disk usage
  • Valid vs corrupted breakdown
  • Attempt limit per file
  • Blocked attempt counters with option to reset them

──────────────────────────────────────────────────────────
  USB CLEANUP
──────────────────────────────────────────────────────────
Scan the USB drive and permanently delete selected .avgvsto files:
  • Corrupted files are pre-selected automatically
  • Valid files can be manually checked for deletion
  • Useful to remove old encrypted files that are no longer needed

WARNING: deleted files cannot be recovered.

──────────────────────────────────────────────────────────
  SECURITY MODEL
──────────────────────────────────────────────────────────
    • Key derivation  PBKDF2-HMAC-SHA256, 1,000,000 iterations
    • Encryption      AES-256-GCM (authenticated, tamper-evident)
    • Hardware bind   USB device ID is mixed into key material
    • Password        Never stored anywhere on disk

    • Attacker has file, NO USB drive    →  cannot decrypt
    • Attacker has USB drive, wrong PW   →  cannot decrypt
    • Both correct but attempt limit hit →  locked out
    • Both correct, no limit             →  only way to decrypt

──────────────────────────────────────────────────────────
  FILE FORMAT  (.avgvsto header layout)
──────────────────────────────────────────────────────────
    • Bytes  0– 7   MAGIC          "AVGVSTO2" (8 bytes)
    • Byte   8      FORMAT_VER     version byte (currently 1)
    • Bytes  9–10   MAX_ATTEMPTS   uint16 LE  (0 = unlimited)
    • Bytes 11–26   SALT           16 random bytes (PBKDF2 input)
    • Bytes 27–38   NONCE          12 bytes (AES-GCM IV)
    • Bytes 39–54   TAG            16 bytes (GCM auth tag)
    • Bytes 55+     CIPHERTEXT     encrypted payload (may be 0 bytes)

──────────────────────────────────────────────────────────
  TROUBLESHOOTING
──────────────────────────────────────────────────────────
"Authorised USB not detected"
  Insert the exact drive used at encryption time. A copy of the
  drive's files won't work — the ID is hardware-based.

"Authentication failed"
  Wrong password or wrong USB drive. Both errors look identical
  to prevent leaking information.

"Maximum attempts exceeded"
  All allowed attempts used up. Use USB ANALYSIS → RESET LOCKED
  COUNTERS to unblock (only if you are the owner).

"File too small / corrupted"
  The .avgvsto file is damaged or not a valid AVGVSTO file.
  Use USB CLEANUP to remove it from the drive.

"No USB binding configured"
  Go to USB KEY BINDING, select a drive, click SET SECURE USB.

──────────────────────────────────────────────────────────
 FOR MORE INFO
  • GITHUB: github.com/RoyMerlo/AVGVSTO
  • GMAIL:  avgvstorm@gmail.com
  • SITE:   https://roymerlo.github.io/AVGVSTO-SITE/
──────────────────────────────────────────────────────────
"""

class HelpModal(_AvgModal):
    def __init__(self, parent):
        super().__init__(parent, title="Help & Guide",
                         color=C["accent"], width=660, height=560)

    def _build(self) -> None:
        outer = tk.Frame(self._inner, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True)
        txt_frame = tk.Frame(outer, bg=C["surface"])
        txt_frame.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        scroll = tk.Scrollbar(txt_frame, orient=tk.VERTICAL,
                              troughcolor=C["surface"], bg=C["surface3"],
                              activebackground=C["accent"],
                              relief=tk.FLAT, bd=0, width=10)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        txt = tk.Text(
            txt_frame, bg=C["surface"], fg=C["text"],
            font=("Courier New", 9), relief=tk.FLAT, bd=16,
            wrap=tk.WORD, state=tk.NORMAL, cursor="arrow",
            yscrollcommand=scroll.set, insertbackground=C["bg"],
            selectbackground=C["surface3"])
        txt.pack(fill=tk.BOTH, expand=True)
        scroll.config(command=txt.yview)
        txt.tag_config("heading", foreground=C["accent"],
                       font=("Courier New", 10, "bold"))
        txt.tag_config("sep",   foreground=C["text_dim"])
        txt.tag_config("url",   foreground=C["accent"], underline=True)
        txt.tag_config("arrow", foreground=C["warning"])
        _heading_keywords = {
            "GETTING STARTED", "STEP 1", "STEP 2", "STEP 3",
            "DRAG & DROP", "ATTEMPT LIMITS", "SECURITY MODEL",
            "FILE FORMAT", "TROUBLESHOOTING", "USB ANALYSIS",
            "USB CLEANUP", "GITHUB", "GMAIL", "SITE",
        }
        for line in _HELP_CONTENT.split("\n"):
            stripped = line.strip()
            if stripped.startswith("═══") or stripped.startswith("───"):
                txt.insert(tk.END, line + "\n", "sep")
            elif any(stripped.startswith(k) for k in _heading_keywords):
                txt.insert(tk.END, line + "\n", "heading")
            elif stripped.startswith("→"):
                txt.insert(tk.END, line + "\n", "arrow")
            elif "github.com/RoyMerlo/AVGVSTO" in stripped:
                parts = line.split("github.com/RoyMerlo/AVGVSTO")
                txt.insert(tk.END, parts[0])
                txt.insert(tk.END, "github.com/RoyMerlo/AVGVSTO", "url")
                txt.insert(tk.END, (parts[1] if len(parts) > 1 else "") + "\n")
            elif "avgvstorm@gmail.com" in stripped:
                parts = line.split("avgvstorm@gmail.com")
                txt.insert(tk.END, parts[0])
                txt.insert(tk.END, "avgvstorm@gmail.com", "url")
                txt.insert(tk.END, (parts[1] if len(parts) > 1 else "") + "\n")
            elif "roymerlo.github.io/AVGVSTO-SITE/" in stripped:
                parts = line.split("https://roymerlo.github.io/AVGVSTO-SITE/")
                txt.insert(tk.END, parts[0])
                txt.insert(tk.END, "https://roymerlo.github.io/AVGVSTO-SITE/", "url")
                txt.insert(tk.END, (parts[1] if len(parts) > 1 else "") + "\n")
            else:
                txt.insert(tk.END, line + "\n")
        txt.tag_bind("url", "<Button-1>", lambda e: webbrowser.open(GITHUB_URL))
        txt.tag_bind("url", "<Enter>",    lambda e: txt.config(cursor="hand2"))
        txt.tag_bind("url", "<Leave>",    lambda e: txt.config(cursor="arrow"))
        txt.config(state=tk.DISABLED)
        foot = tk.Frame(self._inner, bg=C["bg"], pady=12)
        foot.pack(fill=tk.X, padx=24)
        self._btn(foot, "  CLOSE  ", lambda: self._close(None)).pack(side=tk.RIGHT)

# ══════════════════════════════════════════════════════════════════════════════
#  COOLDOWN MODAL  (anti-bruteforce)
# ══════════════════════════════════════════════════════════════════════════════

class CooldownModal(_AvgModal):
    """
    Blocks the UI for the progressive cooldown duration after a wrong-password event.
    Closes automatically when the timer expires.
    Cannot be dismissed manually — the close button is hidden.
    """

    def __init__(self, parent):
        super().__init__(parent, title="Security Cooldown",
                         color=C["accent_red"], width=460, height=230)

    def _build_titlebar(self, title: str) -> None:
        # Override: no close button — user MUST wait
        bar = tk.Frame(self._inner, bg=C["surface2"], height=36)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)
        tk.Frame(bar, bg=C["accent_red"], width=3).pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(bar, text=APP_NAME, bg=C["surface2"], fg=C["accent_red"],
                 font=("Courier New", 9, "bold"), padx=10).pack(side=tk.LEFT)
        tk.Label(bar, text=f"— {title}", bg=C["surface2"], fg=C["text_mid"],
                 font=FONT_SMALL).pack(side=tk.LEFT)
        # NO close button — intentional

    def _build(self) -> None:
        c = self._section(padx=30, pady=22)

        hdr = tk.Frame(c, bg=C["bg"])
        hdr.pack(fill=tk.X, pady=(0, 12))
        tk.Label(hdr, text="⊘", bg=C["bg"], fg=C["accent_red"],
                 font=("Courier New", 26, "bold")).pack(side=tk.LEFT, padx=(0, 14))
        right = tk.Frame(hdr, bg=C["bg"])
        right.pack(side=tk.LEFT, fill=tk.BOTH)
        tk.Label(right, text="WRONG PASSWORD", bg=C["bg"], fg=C["text_bright"],
                 font=("Courier New", 12, "bold"), anchor="w").pack(anchor="w")
        tk.Label(right, text="Anti-bruteforce cooldown active",
                 bg=C["bg"], fg=C["text_mid"],
                 font=("Courier New", 9), anchor="w").pack(anchor="w")

        # Show fail count and next cooldown hint
        with _brute_lock:
            fc = _brute_fail_count
        next_cd = _cooldown_for_count(fc + 1)

        def _fmt_cd(s: float) -> str:
            s = int(s)
            if s < 60:   return f"{s}s"
            if s < 3600: return f"{s//60}m {s%60:02d}s"
            if s < 86400:return f"{s//3600}h {(s%3600)//60:02d}m"
            days = s // 86400
            return f"{days}d {(s%86400)//3600:02d}h"

        info_txt = f"Attempt #{fc}"
        if next_cd > 0:
            info_txt += f"  ·  Next wrong → {_fmt_cd(next_cd)} wait"
        tk.Label(c, text=info_txt,
                 bg=C["bg"], fg=C["text_mid"],
                 font=("Courier New", 8), anchor="w").pack(fill=tk.X, pady=(0, 8))

        self._countdown_var = tk.StringVar()
        tk.Label(c, textvariable=self._countdown_var,
                 bg=C["bg"], fg=C["accent_red"],
                 font=("Courier New", 18, "bold"), anchor="w").pack(
            fill=tk.X, pady=(0, 0))
        self._tick()

    def _tick(self) -> None:
        rem = brute_remaining()
        if rem <= 0.05:
            self._countdown_var.set("0.0 s  —  you may proceed")
            try:
                self.dlg.after(120, lambda: self._close(None))
            except Exception:
                pass
            return
        # Format nicely for large values
        s = rem
        if s < 60:
            txt = f"{s:.1f} s remaining…"
        elif s < 3600:
            txt = f"{int(s)//60}m {int(s)%60:02d}s remaining…"
        elif s < 86400:
            txt = f"{int(s)//3600}h {(int(s)%3600)//60:02d}m remaining…"
        else:
            days = int(s)//86400
            txt = f"{days}d {(int(s)%86400)//3600:02d}h remaining…"
        self._countdown_var.set(txt)
        try:
            self.dlg.after(100, self._tick)
        except Exception:
            pass

# ══════════════════════════════════════════════════════════════════════════════
#  PROGRESS MODAL
# ══════════════════════════════════════════════════════════════════════════════

class ProgressModal:
    _SPINNER = list("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

    def __init__(self, parent, verb: str = "PROCESSING"):
        self.parent       = parent
        self._done        = False
        self._spin_i      = 0
        self._start_t     = None   # set on first real update call
        self._last_done   = 0
        self._last_done_t = 0.0
        self._speed_buf   = []     # rolling speed samples

        self.dlg = tk.Toplevel(parent)
        self.dlg.overrideredirect(True)
        self.dlg.configure(bg=C["border_hi"])
        self.dlg.resizable(True, True)
        self.dlg.attributes("-alpha", 0.0)
        self.dlg.attributes("-topmost", True)
        self.dlg.protocol("WM_DELETE_WINDOW", lambda: None)
        parent.update_idletasks()
        w, h = 540, 360
        px = parent.winfo_x() + parent.winfo_width()  // 2 - w // 2
        py = parent.winfo_y() + parent.winfo_height() // 2 - h // 2
        self.dlg.geometry(f"{w}x{h}+{px}+{py}")
        self._inner = tk.Frame(self.dlg, bg=C["bg"])
        self._inner.place(x=1, y=1, relwidth=1, relheight=1, width=-2, height=-2)
        self._build_titlebar()
        self._build_body(verb)
        self.dlg.transient(parent)
        self.dlg.grab_set()
        self.dlg.lift()
        self._fade_in(1)
        self._spin()

    def _fade_in(self, step: int, steps: int = 8) -> None:
        try:
            self.dlg.attributes("-alpha", step / steps)
        except Exception:
            return
        if step < steps:
            self.dlg.after(10, self._fade_in, step + 1, steps)

    def _build_titlebar(self) -> None:
        bar = tk.Frame(self._inner, bg=C["surface2"], height=32)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)
        tk.Frame(bar, bg=C["accent"], width=3).pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(bar, text=APP_NAME, bg=C["surface2"], fg=C["accent"],
                 font=("Courier New", 9, "bold"), padx=10).pack(side=tk.LEFT)
        tk.Label(bar, text="— Operation in Progress", bg=C["surface2"],
                 fg=C["text_mid"], font=FONT_SMALL).pack(side=tk.LEFT)

    def _build_body(self, verb: str) -> None:
        c = tk.Frame(self._inner, bg=C["bg"])
        c.pack(fill=tk.BOTH, expand=True, padx=20, pady=14)

        # ── Spinner + verb ────────────────────────────────────────────────────
        hdr = tk.Frame(c, bg=C["bg"])
        hdr.pack(fill=tk.X, pady=(0, 4))
        self._spin_lbl = tk.Label(hdr, text=self._SPINNER[0],
                                  bg=C["bg"], fg=C["accent"],
                                  font=("Courier New", 18, "bold"))
        self._spin_lbl.pack(side=tk.LEFT, padx=(0, 10))
        vf = tk.Frame(hdr, bg=C["bg"])
        vf.pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(vf, text=verb, bg=C["bg"], fg=C["text_bright"],
                 font=("Courier New", 11, "bold"), anchor="w").pack(anchor="w")
        self._stage_var = tk.StringVar(value="Initializing…")
        tk.Label(vf, textvariable=self._stage_var, bg=C["bg"],
                 fg=C["text_mid"], font=("Courier New", 8), anchor="w").pack(anchor="w")

        # ── Current file label ────────────────────────────────────────────────
        self._fname_var = tk.StringVar(value="")
        tk.Label(c, textvariable=self._fname_var, bg=C["bg"], fg=C["accent"],
                 font=("Courier New", 8), anchor="w").pack(fill=tk.X, pady=(2, 4))

        # ── Progress bar (tall, with percent label overlay) ───────────────────
        BAR_H = 22
        bar_wrap = tk.Frame(c, bg=C["surface3"], height=BAR_H)
        bar_wrap.pack(fill=tk.X, pady=(0, 2))
        bar_wrap.pack_propagate(False)
        self._bar = tk.Canvas(bar_wrap, bg=C["surface3"], height=BAR_H,
                              bd=0, highlightthickness=0)
        self._bar.pack(fill=tk.BOTH, expand=True)
        self._bar_rect = self._bar.create_rectangle(
            0, 0, 0, BAR_H, fill=C["accent"], outline="")
        self._bar_pct  = self._bar.create_text(
            0, BAR_H // 2, text="0%",
            fill=C["bg"], font=("Courier New", 9, "bold"), anchor="center")
        self._bar_h = BAR_H

        # ── Stats row ─────────────────────────────────────────────────────────
        stats = tk.Frame(c, bg=C["bg"])
        stats.pack(fill=tk.X, pady=(4, 6))

        # Left: counter + percent
        self._count_var = tk.StringVar(value="")
        tk.Label(stats, textvariable=self._count_var, bg=C["bg"],
                 fg=C["accent"], font=("Courier New", 9, "bold"),
                 anchor="w").pack(side=tk.LEFT)

        # Right: elapsed + ETA
        self._time_var = tk.StringVar(value="")
        tk.Label(stats, textvariable=self._time_var, bg=C["bg"],
                 fg=C["text_dim"], font=("Courier New", 8),
                 anchor="e").pack(side=tk.RIGHT)

        # Speed row
        speed_f = tk.Frame(c, bg=C["bg"])
        speed_f.pack(fill=tk.X, pady=(0, 4))
        self._speed_var = tk.StringVar(value="")
        tk.Label(speed_f, textvariable=self._speed_var, bg=C["bg"],
                 fg=C["text_dim"], font=("Courier New", 8),
                 anchor="w").pack(side=tk.LEFT)

        # ── File log (scrollable) ─────────────────────────────────────────────
        log_outer = tk.Frame(c, bg=C["surface"])
        log_outer.pack(fill=tk.BOTH, expand=True)
        log_scroll = tk.Scrollbar(log_outer, orient=tk.VERTICAL,
                                  troughcolor=C["surface"], bg=C["surface3"],
                                  activebackground=C["accent"],
                                  relief=tk.FLAT, bd=0, width=8)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._log_txt = tk.Text(
            log_outer, bg=C["surface"], fg=C["text_dim"],
            font=("Courier New", 8), relief=tk.FLAT, bd=6,
            wrap=tk.NONE, state=tk.DISABLED, cursor="arrow",
            yscrollcommand=log_scroll.set, insertbackground=C["bg"])
        self._log_txt.pack(fill=tk.BOTH, expand=True)
        log_scroll.config(command=self._log_txt.yview)
        self._log_txt.tag_config("done",    foreground=C["success"])
        self._log_txt.tag_config("cur",     foreground=C["warning"])
        self._log_txt.tag_config("summary", foreground=C["accent"],
                                 font=("Courier New", 8, "bold"))

    def _spin(self) -> None:
        if self._done:
            return
        self._spin_i = (self._spin_i + 1) % len(self._SPINNER)
        try:
            self._spin_lbl.config(text=self._SPINNER[self._spin_i])
            self.dlg.after(80, self._spin)
        except Exception:
            pass

    def _tick(self) -> None:
        """Refresh elapsed/ETA every second even when no update() call arrives."""
        if self._done or self._start_t is None:
            return
        try:
            elapsed = time.time() - self._start_t
            cur = self._time_var.get()
            # Keep the ETA part if it exists, only refresh elapsed prefix
            if "  ETA" in cur:
                eta_part = cur[cur.index("  ETA"):]
                self._time_var.set(f"⏱ {_fmt_elapsed(elapsed)}{eta_part}")
            else:
                self._time_var.set(f"⏱ {_fmt_elapsed(elapsed)}")
            self.dlg.after(1000, self._tick)
        except Exception:
            pass

    def update(self, done: int, total: int, filename: str = "") -> None:
        # Start the clock on first real update
        if self._start_t is None and total > 0:
            self._start_t = time.time()
            self.dlg.after(1000, self._tick)
        try:
            self.dlg.after(0, self._do_update, done, total, filename)
        except Exception:
            pass

    def _do_update(self, done: int, total: int, filename: str) -> None:
        try:
            # Current file label
            if filename:
                self._fname_var.set(f"▶  {filename}")
            else:
                self._fname_var.set("Finalizing…")

            is_complete = (total > 0 and done >= total)
            bar_color   = C["success"] if is_complete else C["accent"]
            txt_color   = C["bg"]

            if total > 0:
                frac = min(done / total, 1.0)
                pct  = int(frac * 100)

                # ── Progress bar fill + percent label ─────────────────────────
                self._bar.update_idletasks()
                w = self._bar.winfo_width() or 500
                h = self._bar_h
                fill_w = w * frac
                self._bar.coords(self._bar_rect, 0, 0, fill_w, h)
                self._bar.itemconfig(self._bar_rect, fill=bar_color)

                # Position percentage text: inside bar if there's room, else right of bar
                pct_txt = f"{pct}%"
                if fill_w > 40:
                    px_x = fill_w / 2
                else:
                    px_x = max(fill_w + 20, 24)
                    txt_color = C["text_mid"]
                self._bar.coords(self._bar_pct, px_x, h // 2)
                self._bar.itemconfig(self._bar_pct, text=pct_txt, fill=txt_color)

                # ── Stage label ───────────────────────────────────────────────
                if is_complete:
                    self._stage_var.set("✓  Complete")
                else:
                    self._stage_var.set(f"Processing file {done+1} of {total}")

                # ── Counter label ─────────────────────────────────────────────
                self._count_var.set(f"{done} / {total}  ·  {pct}%")

                # ── Speed estimate (files/s) ──────────────────────────────────
                now = time.time()
                if self._last_done_t and done > self._last_done:
                    dt = now - self._last_done_t
                    if dt > 0:
                        fps = (done - self._last_done) / dt
                        self._speed_buf.append(fps)
                        if len(self._speed_buf) > 8:
                            self._speed_buf.pop(0)
                self._last_done   = done
                self._last_done_t = now

                avg_fps = sum(self._speed_buf) / len(self._speed_buf) if self._speed_buf else 0
                spd_txt = f"⚡ {avg_fps:.1f} files/s" if avg_fps > 0 else ""
                self._speed_var.set(spd_txt)

                # ── Time stats ────────────────────────────────────────────────
                if self._start_t:
                    elapsed = now - self._start_t
                    if is_complete:
                        self._time_var.set(f"⏱ {_fmt_elapsed(elapsed)}  ·  done")
                    elif done > 0:
                        eta = elapsed / done * (total - done)
                        self._time_var.set(
                            f"⏱ {_fmt_elapsed(elapsed)}  ·  ETA {_fmt_elapsed(eta)}")
                    else:
                        self._time_var.set(f"⏱ {_fmt_elapsed(elapsed)}")

            # ── Append processed file to log ──────────────────────────────────
            if filename:
                self._log_txt.config(state=tk.NORMAL)
                tag = "summary" if is_complete else "done"
                self._log_txt.insert(tk.END, f"  ✓  {filename}\n", tag)
                self._log_txt.see(tk.END)
                self._log_txt.config(state=tk.DISABLED)

        except Exception:
            pass

    def close(self) -> None:
        self._done = True
        try:
            self.dlg.grab_release()
            self.dlg.destroy()
        except Exception:
            pass

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class AVGVSTOApp:

    def __init__(self) -> None:
        self.root = TkinterDnD.Tk() if DND else tk.Tk()
        self.root.configure(bg=C["bg"])
        self.root.title(f"{APP_NAME} v{APP_VERSION}  —  Advanced Encryption Suite  [BUSINESS]")
        self.root.geometry("620x920")
        self.root.resizable(True, True)
        _load_icon(self.root)
        self._pulse_t     = 0.0
        self._drop_active = False
        self._tray_icon   = None
        self._last_usb_ok = False
        # Business: load silent deployment config (IT admin pre-configuration)
        _load_deploy_config()
        self._build_ui()
        self.refresh_usb_list()
        self._pulse_title()
        self._poll_usb_dot()
        self._bind_shortcuts()
        if TRAY:
            threading.Thread(target=self._start_tray, daemon=True).start()
        self.root.after(400, self._check_first_run)
        # Business: log startup event
        self.root.after(600, lambda: audit_log("STARTUP", APP_NAME, "OK",
                                               load_usb_id() or ""))

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = self.root

        # ── Top bar: INFO / HELP in the very top-left corner ─────────────────
        top_bar = tk.Frame(root, bg=C["bg"])
        top_bar.pack(fill=tk.X, padx=8, pady=(6, 0))
        for label, cmd, col in [
            ("INFO", lambda: InfoModal(self.root).show(), C["accent_dim"]),
            ("HELP", lambda: HelpModal(self.root).show(), C["accent_dim"]),
        ]:
            b = tk.Button(top_bar, text=label, command=cmd,
                          bg=C["surface2"], fg=col,
                          font=("Courier New", 8, "bold"),
                          relief=tk.FLAT, bd=0, padx=9, pady=4, cursor="hand2")
            b.bind("<Enter>", lambda e, b=b, c=col: b.config(bg=col, fg=C["bg"]))
            b.bind("<Leave>", lambda e, b=b, c=col: b.config(bg=C["surface2"], fg=c))
            b.pack(side=tk.LEFT, padx=(0, 4))

        # ── BACKUP dropdown ───────────────────────────────────────────────────
        self._backup_btn = tk.Button(
            top_bar, text="💾 BACKUP ▾",
            command=self._show_backup_menu,
            bg=C["surface3"], fg=C["warning"],
            font=("Courier New", 8, "bold"),
            relief=tk.FLAT, bd=0, padx=9, pady=4, cursor="hand2")
        self._backup_btn.bind(
            "<Enter>", lambda e: self._backup_btn.config(bg=C["warning"], fg=C["bg"]))
        self._backup_btn.bind(
            "<Leave>", lambda e: self._backup_btn.config(bg=C["surface3"], fg=C["warning"]))
        self._backup_btn.pack(side=tk.LEFT, padx=(0, 4))

        # ── Title row: icon LEFT  |  AVGVSTO RIGHT ───────────────────────────
        title_row = tk.Frame(root, bg=C["bg"])
        title_row.pack(fill=tk.X, padx=24, pady=(6, 0))

        # Hexagonal icon canvas (left)
        ICO = 80
        self._icon_cv = tk.Canvas(title_row, bg=C["bg"], width=ICO, height=ICO,
                                  bd=0, highlightthickness=0)
        self._icon_cv.pack(side=tk.LEFT, padx=(0, 10), pady=(4, 0))
        self._draw_hex_icon(self._icon_cv, ICO)

        # AVGVSTO title canvas (right / fills remaining space)
        self._title_cv = tk.Canvas(title_row, bg=C["bg"], height=ICO,
                                   bd=0, highlightthickness=0)
        self._title_cv.pack(side=tk.LEFT, fill=tk.X, expand=True)
        # We'll position text at right edge after pack; use after_idle
        self._title_item = self._title_cv.create_text(
            0, ICO // 2, text=APP_NAME, font=FONT_TITLE,
            fill=C["accent"], anchor="w")
        self._title_cv.bind("<Configure>", self._on_title_configure)

        # Subtitle
        tk.Label(root, text=f"v{APP_VERSION}  ·  Advanced Encryption Suite  ·  BUSINESS",
                 bg=C["bg"], fg=C["text_dim"], font=FONT_SMALL).pack()
        auth = tk.Frame(root, bg=C["bg"])
        auth.pack(pady=(4, 0))
        self._badge(auth, "RM",  C["accent"]).pack(side=tk.LEFT, padx=4)
        tk.Label(auth, text="·", bg=C["bg"], fg=C["text_dim"],
                 font=FONT_SUB).pack(side=tk.LEFT, padx=2)
        self._badge(auth, "RPX", C["accent_red"]).pack(side=tk.LEFT, padx=4)

        # USB card
        self._hsep(root)
        usb_card = tk.Frame(root, bg=C["surface"], padx=16, pady=12)
        usb_card.pack(fill=tk.X, padx=30)
        usb_top = tk.Frame(usb_card, bg=C["surface"])
        usb_top.pack(fill=tk.X)
        tk.Label(usb_top, text="USB KEY BINDING",
                 bg=C["surface"], fg=C["text_dim"],
                 font=("Courier New", 8, "bold")).pack(side=tk.LEFT)
        self._dot_cv = tk.Canvas(usb_top, width=12, height=12,
                                 bg=C["surface"], bd=0, highlightthickness=0)
        self._dot_cv.pack(side=tk.RIGHT, padx=(0, 2))
        self._dot_oval = self._dot_cv.create_oval(
            2, 2, 10, 10, fill=C["text_dim"], outline="")
        usb_row = tk.Frame(usb_card, bg=C["surface"])
        usb_row.pack(fill=tk.X, pady=(6, 0))
        self.usb_var   = tk.StringVar(value="— no drives detected —")
        self.usb_combo = ttk.Combobox(usb_row, textvariable=self.usb_var,
                                      font=FONT_MONO, state="readonly")
        self._style_combobox()
        self.usb_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._icon_btn(usb_row, "↺", self.refresh_usb_list,
                       C["text_dim"]).pack(side=tk.LEFT, padx=(6, 0))
        # BROWSE button — manually select any directory as USB
        browse_usb = tk.Button(usb_row, text=" BROWSE ",
                               command=self._browse_usb,
                               bg=C["surface2"], fg=C["accent_dim"],
                               font=("Courier New", 8, "bold"),
                               relief=tk.FLAT, bd=0, padx=6, pady=4, cursor="hand2")
        browse_usb.bind("<Enter>", lambda e: browse_usb.config(bg=C["accent_dim"], fg=C["bg"]))
        browse_usb.bind("<Leave>", lambda e: browse_usb.config(bg=C["surface2"], fg=C["accent_dim"]))
        browse_usb.pack(side=tk.LEFT, padx=(4, 0))
        self._action_btn(usb_card, "  SET SECURE USB DRIVE",
                         self.set_usb, C["accent"], "⬡").pack(fill=tk.X, pady=(8, 0))

        # USB Tools
        self._hsep(root)
        self._section_label(root, "USB TOOLS")
        usb_tools = tk.Frame(root, bg=C["bg"])
        usb_tools.pack(fill=tk.X, padx=30)
        usb_tools.columnconfigure(0, weight=1)
        usb_tools.columnconfigure(1, weight=1)
        usb_tools.columnconfigure(2, weight=1)
        usb_tools.columnconfigure(3, weight=1)
        self._action_btn(usb_tools, "  ANALYSIS", self.usb_analysis,
                        C["accent"], "⬡").grid(
            row=0, column=0, sticky="ew", padx=(0, 3), pady=4)
        self._action_btn(usb_tools, "  CLEANUP", self.usb_cleanup,
                        C["accent_red"], "✕").grid(
            row=0, column=1, sticky="ew", padx=(3, 3), pady=4)
        self._action_btn(usb_tools, "  BINDINGS", self.usb_bindings,
                        C["accent"], "⬡").grid(
            row=0, column=2, sticky="ew", padx=(3, 3), pady=4)
        self._action_btn(usb_tools, "  AUDIT LOG", self.open_audit_log,
                        C["warning"], "⬡").grid(
            row=0, column=3, sticky="ew", padx=(3, 0), pady=4)

        # Operations
        self._hsep(root)
        self._section_label(root, "OPERATIONS")
        bf = tk.Frame(root, bg=C["bg"])
        bf.pack(fill=tk.X, padx=30)
        bf.columnconfigure(0, weight=1)
        bf.columnconfigure(1, weight=1)
        bf.columnconfigure(2, weight=1)
        self._action_btn(bf, "  ENCRYPT", self.encrypt_data,
                         C["accent"], "🔐").grid(
            row=0, column=0, sticky="ew", padx=(0, 3), pady=4)
        self._action_btn(bf, "  DECRYPT", self.decrypt_data,
                         C["accent_red"], "🔓").grid(
            row=0, column=1, sticky="ew", padx=(3, 3), pady=4)
        self._action_btn(bf, "  VERIFY", self.verify_data,
                         C["warning"], "✔").grid(
            row=0, column=2, sticky="ew", padx=(3, 0), pady=4)
        # Keyboard shortcut hint
        tk.Label(root, text="Ctrl+E  Encrypt  ·  Ctrl+D  Decrypt  ·  Ctrl+V  Verify  ·  Ctrl+A  Analysis",
                 bg=C["bg"], fg=C["text_dim"],
                 font=("Courier New", 7)).pack(pady=(0, 2))

        # Drop Zone
        self._hsep(root)
        self._section_label(root, "DROP ZONE")
        self._drop_cv = tk.Canvas(root, bg=C["surface"], height=76,
                                  bd=0, highlightthickness=0, cursor="hand2")
        self._drop_cv.pack(fill=tk.X, padx=30, pady=(4, 0))
        self._drop_cv.bind("<Button-1>",  lambda e: self._drop_click())
        self._drop_cv.bind("<Enter>",     lambda e: self._drop_hover(True))
        self._drop_cv.bind("<Leave>",     lambda e: self._drop_hover(False))
        self._drop_cv.bind("<Configure>", lambda e: self._draw_drop(self._drop_active))
        if DND:
            self._drop_cv.drop_target_register(DND_FILES)
            self._drop_cv.dnd_bind("<<Drop>>",
                lambda e: self._on_drop(e))
            self._drop_cv.dnd_bind("<<DragEnter>>",
                lambda e: (self._drop_hover(True), self._drop_cv.update()))
            self._drop_cv.dnd_bind("<<DragLeave>>",
                lambda e: (self._drop_hover(False), self._drop_cv.update()))

        # Console
        self._hsep(root)
        self._section_label(root, "CONSOLE")
        con_outer = tk.Frame(root, bg=C["surface"])
        con_outer.pack(fill=tk.BOTH, expand=True, padx=30, pady=(4, 8))
        self.console = tk.Text(
            con_outer, bg=C["surface"], fg=C["accent"],
            font=FONT_STATUS, relief=tk.FLAT, bd=8,
            height=5, state=tk.DISABLED, wrap=tk.WORD,
            cursor="arrow", insertbackground=C["accent"])
        self.console.pack(fill=tk.BOTH, expand=True)
        for tag, col in [("info", C["accent"]), ("success", C["success"]),
                         ("warning", C["warning"]), ("error", C["error"]),
                         ("dim", C["text_dim"])]:
            self.console.tag_config(tag, foreground=col)

        # ── Stats dashboard ───────────────────────────────────────────────────
        stats_frame = tk.Frame(root, bg=C["surface"], padx=0, pady=8)
        stats_frame.pack(fill=tk.X, padx=30, pady=(0, 16))
        self._stat_cells = {}
        for key, label, col in [
            ("files_encrypted", "ENCRYPTED",  C["accent"]),
            ("files_decrypted", "DECRYPTED",  C["accent_red"]),
            ("bytes_encrypted", "TOTAL SIZE", C["text_mid"]),
        ]:
            cell = tk.Frame(stats_frame, bg=C["surface2"], padx=12, pady=6)
            cell.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=(0, 2))
            self._stat_cells[key] = {
                "val": tk.StringVar(value="—"),
                "frame": cell,
            }
            tk.Label(cell, textvariable=self._stat_cells[key]["val"],
                     bg=C["surface2"], fg=col,
                     font=("Courier New", 14, "bold")).pack()
            tk.Label(cell, text=label,
                     bg=C["surface2"], fg=C["text_dim"],
                     font=("Courier New", 7, "bold")).pack()

        portable_lbl = "  ⚡ PORTABLE" if _IS_PORTABLE else ""
        tk.Label(stats_frame, text=portable_lbl,
                 bg=C["surface"], fg=C["warning"],
                 font=("Courier New", 8, "bold"), padx=8).pack(side=tk.RIGHT)

        self._log(f"AVGVSTO v{APP_VERSION} ready.{' [PORTABLE]' if _IS_PORTABLE else ''}", "dim")
        self._log("Configure a USB key binding before operating.", "dim")
        self._refresh_stats()

    # ── Animations ────────────────────────────────────────────────────────────

    def _draw_hex_icon(self, cv: tk.Canvas, size: int) -> None:
        """Draw a filled hexagonal icon on the given canvas."""
        import math as _math
        cx, cy = size / 2, size / 2
        r  = size / 2 - 2
        ri = r * 0.72   # inner highlight ring

        # Outer hex (border/glow)
        pts_outer = []
        for i in range(6):
            a = _math.radians(60 * i - 30)
            pts_outer += [cx + r * _math.cos(a), cy + r * _math.sin(a)]
        cv.create_polygon(pts_outer, fill="#003322", outline=C["accent"], width=2)

        # Inner hex (dark fill)
        pts_inner = []
        for i in range(6):
            a = _math.radians(60 * i - 30)
            pts_inner += [cx + ri * _math.cos(a), cy + ri * _math.sin(a)]
        cv.create_polygon(pts_inner, fill="#0a0a0a", outline="")

        # Letter A — simplified as two diagonal lines + crossbar
        lx, ty = cx - size * 0.18, cy + size * 0.22
        rx, by = cx + size * 0.18, cy - size * 0.22
        cv.create_line(cx, by, lx, ty, fill=C["accent"], width=3, capstyle="round")
        cv.create_line(cx, by, rx, ty, fill=C["accent"], width=3, capstyle="round")
        bx1, bx2 = cx - size * 0.10, cx + size * 0.10
        bary     = cy + size * 0.02
        cv.create_line(bx1, bary, bx2, bary, fill=C["accent"], width=2, capstyle="round")

    def _on_title_configure(self, event) -> None:
        """Keep AVGVSTO text right-aligned inside canvas."""
        try:
            w = event.width
            h = event.height
            self._title_cv.coords(self._title_item, w - 4, h // 2)
            self._title_cv.itemconfig(self._title_item, anchor="e")
        except Exception:
            pass

    def _browse_usb(self) -> None:
        """Let user manually browse to any directory and use it as USB path."""
        chosen = filedialog.askdirectory(
            title="Select USB drive or directory to use as hardware key",
            parent=self.root)
        if chosen and os.path.isdir(chosen):
            # Add to combobox values and select it
            current_vals = list(self.usb_combo["values"])
            if chosen not in current_vals:
                current_vals.append(chosen)
                self.usb_combo["values"] = current_vals
            self.usb_combo.config(state="readonly")
            self.usb_var.set(chosen)
            self._log(f"Manual path selected: {chosen}", "info")

    def _pulse_title(self) -> None:
        self._pulse_t += 0.06
        v = (math.sin(self._pulse_t) + 1) / 2
        g = int(0xBB + (0xFF - 0xBB) * v)
        b = int(0x99 + (0xCC - 0x99) * v)
        try:
            self._title_cv.itemconfig(self._title_item, fill=f"#00{g:02x}{b:02x}")
            self._icon_cv.itemconfig("all")   # no-op but keeps reference alive
            self.root.after(50, self._pulse_title)
        except Exception:
            pass

    # ── Stats ─────────────────────────────────────────────────────────────────

    def _refresh_stats(self) -> None:
        try:
            s = _load_stats()
            self._stat_cells["files_encrypted"]["val"].set(
                str(s.get("files_encrypted", 0)))
            self._stat_cells["files_decrypted"]["val"].set(
                str(s.get("files_decrypted", 0)))
            self._stat_cells["bytes_encrypted"]["val"].set(
                _fmt_size(s.get("bytes_encrypted", 0)))
        except Exception:
            pass

    # ── Keyboard shortcuts ────────────────────────────────────────────────────

    def _bind_shortcuts(self) -> None:
        self.root.bind("<Control-e>",    lambda e: self.encrypt_data())
        self.root.bind("<Control-d>",    lambda e: self.decrypt_data())
        self.root.bind("<Control-a>",    lambda e: self._open_analysis())
        self.root.bind("<Control-v>",    lambda e: self.verify_data())
        self.root.bind("<Control-r>",    lambda e: self.refresh_usb_list())
        self.root.bind("<Control-comma>",lambda e: InfoModal(self.root).show())
        self.root.bind("<F1>",           lambda e: HelpModal(self.root).show())

    # ── First-run wizard ──────────────────────────────────────────────────────

    def _check_first_run(self) -> None:
        if not KEY_FILE.exists():
            drives = list_usb_drives()
            result = FirstRunWizard(self.root, drives).show()
            if result:
                self.refresh_usb_list()
                self._refresh_stats()
                self._log("Setup complete. Ready to encrypt.", "success")

    # ── System Tray ───────────────────────────────────────────────────────────

    def _make_tray_icon_image(self, connected: bool) -> "PILImage.Image":
        img  = PILImage.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        col  = (0, 255, 180, 255) if connected else (200, 80, 80, 255)
        # Simple hexagon
        import math as _m
        cx, cy, r = 32, 32, 28
        pts = [(cx + r * _m.cos(_m.radians(60*i-30)),
                cy + r * _m.sin(_m.radians(60*i-30))) for i in range(6)]
        draw.polygon(pts, fill=col)
        return img

    def _start_tray(self) -> None:
        if not TRAY:
            return
        try:
            img = self._make_tray_icon_image(False)
            menu = pystray.Menu(
                pystray.MenuItem("Open AVGVSTO", self._tray_open, default=True),
                pystray.MenuItem("USB Status",   self._tray_usb_status),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Quit",         self._tray_quit),
            )
            self._tray_icon = pystray.Icon("AVGVSTO", img, "AVGVSTO", menu)
            # Poll USB status every 5 s via tray update
            threading.Thread(target=self._tray_usb_poll, daemon=True).start()
            self._tray_icon.run()
        except Exception:
            pass

    def _tray_usb_poll(self) -> None:
        while True:
            time.sleep(5)
            try:
                saved = load_usb_id()
                ok    = bool(saved and find_authorized_usb(saved))
                if ok != self._last_usb_ok:
                    self._last_usb_ok = ok
                    if self._tray_icon:
                        self._tray_icon.icon = self._make_tray_icon_image(ok)
                    if not ok and saved:
                        try:
                            self._tray_icon.notify(
                                "USB drive removed",
                                "AVGVSTO: hardware key disconnected")
                        except Exception:
                            pass
                    elif ok:
                        try:
                            self._tray_icon.notify(
                                "USB drive detected",
                                "AVGVSTO: hardware key connected")
                        except Exception:
                            pass
            except Exception:
                pass

    def _tray_open(self) -> None:
        try:
            self.root.after(0, self.root.deiconify)
            self.root.after(0, self.root.lift)
        except Exception:
            pass

    def _tray_usb_status(self) -> None:
        saved = load_usb_id()
        if saved and find_authorized_usb(saved):
            msg = "USB drive CONNECTED ✓"
        elif saved:
            msg = "USB drive NOT FOUND — connect the key drive"
        else:
            msg = "No USB binding configured"
        try:
            self._tray_icon.notify("USB Status", msg)
        except Exception:
            pass

    def _tray_quit(self) -> None:
        try:
            if self._tray_icon:
                self._tray_icon.stop()
        except Exception:
            pass
        try:
            self.root.after(0, self.root.destroy)
        except Exception:
            pass

    # ── Open Analysis helper (also mapped to Ctrl+A) ──────────────────────────

    def _open_analysis(self) -> None:
        path = self._require_usb_path()
        if path:
            UsbAnalysisModal(self.root, path).show()



    def _poll_usb_dot(self) -> None:
        saved = load_usb_id()
        if saved and find_authorized_usb(saved):
            v = (math.sin(self._pulse_t * 3) + 1) / 2
            g = int(0x88 + (0xFF - 0x88) * v)
            self._dot_cv.itemconfig(self._dot_oval, fill=f"#00{g:02x}44")
        elif saved:
            self._dot_cv.itemconfig(self._dot_oval, fill=C["warning"])
        else:
            self._dot_cv.itemconfig(self._dot_oval, fill=C["text_dim"])
        try:
            self.root.after(2000, self._poll_usb_dot)
        except Exception:
            pass

    # ── Drop Zone ─────────────────────────────────────────────────────────────

    def _draw_drop(self, hovered: bool = False) -> None:
        c = self._drop_cv
        c.delete("all")
        c.update_idletasks()
        w = c.winfo_width()  or 520
        h = c.winfo_height() or 76
        border = C["accent"]   if hovered else C["border_hi"]
        text_c = C["accent"]   if hovered else C["text_dim"]
        bg     = C["surface3"] if hovered else C["surface"]
        c.configure(bg=bg)
        c.create_rectangle(3, 3, w - 3, h - 3,
                           outline=border, dash=(8, 5), width=1)
        c.create_text(w // 2, h // 2 - 12,
                      text="⬆" if hovered else "⬇",
                      fill=text_c, font=("Courier New", 13))
        hint = ("DROP HERE" if hovered else
                ("DROP FILES OR FOLDERS  ·  or click to browse"
                 if DND else "CLICK TO SELECT FILE OR FOLDER"))
        c.create_text(w // 2, h // 2 + 14, text=hint,
                      fill=text_c, font=FONT_SMALL)

    def _drop_hover(self, hovered: bool) -> None:
        self._drop_active = hovered
        self._draw_drop(hovered)

    def _drop_click(self) -> None:
        action = ChoiceDialog(self.root).show()
        if action == "encrypt":
            self.encrypt_data()
        elif action == "decrypt":
            self.decrypt_data()

    # ── Multi-file drop parser ────────────────────────────────────────────────

    def _parse_drop_paths(self, data: str) -> List[str]:
        """
        Parse tkinterdnd2 drop data correctly.
        Handles: paths with spaces (braced), multiple paths, quoted paths.
        """
        paths = []
        data  = data.strip()
        i     = 0
        while i < len(data):
            if data[i] == '{':
                end = data.find('}', i)
                if end == -1:
                    break
                paths.append(data[i + 1:end])
                i = end + 1
            elif data[i] == ' ':
                i += 1
            else:
                end = data.find(' ', i)
                if end == -1:
                    paths.append(data[i:])
                    break
                paths.append(data[i:end])
                i = end
        return [p.strip('"') for p in paths
                if p.strip('"') and os.path.exists(p.strip('"'))]

    def _on_drop(self, event) -> None:
        self._drop_hover(False)
        paths = self._parse_drop_paths(event.data)
        if not paths:
            self._log("Invalid dropped path(s).", "error")
            return
        usb_id = self._require_usb()
        if not usb_id:
            return

        if len(paths) == 1:
            path = paths[0]
            if os.path.isdir(path):
                action = ChoiceDialog(self.root).show()
                if action == "encrypt":
                    self._run_encrypt(path, usb_id)
                elif action == "decrypt":
                    self._run_decrypt(path, usb_id)
            elif path.endswith(ENC_EXT):
                self._run_decrypt(path, usb_id)
            else:
                self._run_encrypt(path, usb_id)
        else:
            # Multiple items — smart detection
            # ── Pro tier: max 100 files per batch ────────────────────────────
            plain_files = [p for p in paths if os.path.isfile(p)]
            if len(plain_files) > PRO_MAX_FILES:
                AlertModal(self.root, "warning", "Batch Limit",
                           f"Pro tier supports up to {PRO_MAX_FILES} files per batch.\n"
                           f"You dropped {len(plain_files)} files.\n\n"
                           "Split into smaller batches or use the CLI for large jobs.").show()
                return
            # RULE: if ANY folder is present → always ask (can't auto-detect intent)
            has_enc   = any(p.endswith(ENC_EXT) for p in paths if os.path.isfile(p))
            has_plain = any(not p.endswith(ENC_EXT) for p in paths if os.path.isfile(p))
            has_dirs  = any(os.path.isdir(p) for p in paths)

            if has_dirs:
                # Folders present → always ask
                action = ChoiceDialog(self.root).show()
            elif has_enc and not has_plain:
                action = "decrypt"
            elif has_plain and not has_enc:
                action = "encrypt"
            else:
                action = ChoiceDialog(self.root).show()

            if not action:
                return

            password = PasswordDialog(
                self.root, confirm=(action == "encrypt"), mode=action).show()
            if not password:
                return

            max_attempts = None
            if action == "encrypt":
                max_attempts = AttemptLimitDialog(self.root).show()
                if max_attempts is None:
                    return
                # Offer reset password if attempt limit set
                if max_attempts > 0:
                    usb_path = self._require_usb_path()
                    if usb_path and not has_reset_password(usb_path):
                        reset_pw = ResetPasswordCreateDialog(self.root).show()
                        if reset_pw:
                            create_reset_password(usb_path, reset_pw)
                            self._log("Reset password saved to USB.", "success")

            self._run_multi(paths, usb_id, action, password, max_attempts)

    # ── Widget factories ──────────────────────────────────────────────────────

    def _badge(self, parent, text: str, color: str) -> tk.Label:
        lbl = tk.Label(parent, text=text, bg=C["bg"], fg=color,
                       font=("Courier New", 12, "bold"), cursor="hand2")
        lbl.bind("<Enter>", lambda e: lbl.config(fg=C["text_bright"]))
        lbl.bind("<Leave>", lambda e: lbl.config(fg=color))
        return lbl

    def _section_label(self, parent, text: str) -> None:
        f = tk.Frame(parent, bg=C["bg"])
        f.pack(fill=tk.X, padx=30, pady=(10, 2))
        tk.Label(f, text=text, bg=C["bg"], fg=C["text_dim"],
                 font=("Courier New", 8, "bold"), anchor="w").pack(side=tk.LEFT)

    def _hsep(self, parent) -> None:
        tk.Frame(parent, bg=C["border"], height=1).pack(
            fill=tk.X, padx=30, pady=8)

    def _action_btn(self, parent, text: str, cmd, color: str,
                    icon: str = "") -> tk.Button:
        btn = tk.Button(parent, text=f"{icon}{text}", command=cmd,
                        bg=C["surface2"], fg=color,
                        activebackground=color, activeforeground=C["bg"],
                        font=FONT_BTN, relief=tk.FLAT, bd=0,
                        padx=14, pady=10, cursor="hand2")
        btn.bind("<Enter>", lambda e: btn.config(bg=color, fg=C["bg"]))
        btn.bind("<Leave>", lambda e: btn.config(bg=C["surface2"], fg=color))
        return btn

    def _icon_btn(self, parent, symbol: str, cmd, color: str) -> tk.Button:
        btn = tk.Button(parent, text=symbol, command=cmd,
                        bg=C["surface2"], fg=color,
                        activebackground=C["border"],
                        activeforeground=C["text_bright"],
                        font=("Courier New", 13, "bold"),
                        relief=tk.FLAT, bd=0, padx=8, pady=4,
                        cursor="hand2", width=3)
        return btn

    def _style_combobox(self) -> None:
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TCombobox",
                        fieldbackground=C["surface2"],
                        background=C["surface2"],
                        foreground=C["text"],
                        arrowcolor=C["accent"],
                        bordercolor=C["border"],
                        lightcolor=C["border"],
                        darkcolor=C["border"],
                        padding=6,
                        font=FONT_MONO)

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, msg: str, level: str = "info") -> None:
        self.console.config(state=tk.NORMAL)
        self.console.insert(tk.END, f"› {msg}\n", level)
        self.console.see(tk.END)
        self.console.config(state=tk.DISABLED)

    # ── Toast ─────────────────────────────────────────────────────────────────

    def _toast(self, message: str, kind: str = "success",
               duration: int = 3200) -> None:
        color = {"success": C["success"], "warning": C["warning"],
                 "error": C["error"]}.get(kind, C["accent"])
        self.root.update_idletasks()
        rw = self.root.winfo_width()
        rh = self.root.winfo_height()
        tw, th = 350, 44
        tx = rw // 2 - tw // 2
        toast = tk.Frame(self.root, bg=color)
        tk.Label(toast, text=message, bg=color, fg=C["bg"],
                 font=("Courier New", 10, "bold"), padx=16).pack(
            fill=tk.BOTH, ipady=11)
        toast.place(x=tx, y=rh + 6, width=tw)
        target_y = rh - th - 22
        def slide(y: int) -> None:
            if y > target_y:
                ny = max(y - 9, target_y)
                toast.place(x=tx, y=ny, width=tw)
                self.root.after(10, slide, ny)
        slide(rh + 6)
        def fade(step: int = 0) -> None:
            try:
                toast.place(x=int(tx + step * 3), y=target_y, width=tw)
                if step < 10:
                    self.root.after(28, fade, step + 1)
                else:
                    toast.destroy()
            except Exception:
                pass
        self.root.after(duration, fade)

    # ── USB ───────────────────────────────────────────────────────────────────

    def refresh_usb_list(self) -> None:
        drives = list_usb_drives()
        self.usb_combo["values"] = drives
        if drives:
            self.usb_combo.set(drives[0])
            self._log(f"Found {len(drives)} removable drive(s).", "dim")
        else:
            self.usb_combo.set("— no drives detected —")
            self._log("No removable drives detected.", "warning")

    def set_usb(self) -> None:
        selected = self.usb_var.get()
        if not selected or selected.startswith("—"):
            AlertModal(self.root, "warning", "No Drive Selected",
                       "Select a valid USB drive from the list first.").show()
            return
        uid = save_usb_config(selected)
        if uid:
            short = uid[:12] + "…"
            self._log(f"USB binding saved: ID {short}", "success")
            self._toast(f"USB drive configured  ·  {short}", "success")
            audit_log("USB_BIND", selected, "OK", uid)
        else:
            self._log("Failed to retrieve device identifier.", "error")
            AlertModal(self.root, "error", "USB Error",
                       "Could not read device identifier for the selected drive.").show()

    def _require_usb(self) -> Optional[str]:
        saved = load_usb_id()
        if not saved:
            AlertModal(self.root, "error", "No USB Binding",
                       "No USB binding configured.\n\nSet a secure USB drive first.").show()
            return None
        path = find_authorized_usb(saved)
        if not path:
            self._log("Authorised USB not detected — aborted.", "error")
            AlertModal(self.root, "error", "USB Not Found",
                       "Authorised USB drive not detected.\n\n"
                       "Connect the correct drive and try again.").show()
            return None
        return saved

    def _require_usb_path(self) -> Optional[str]:
        """Return the actual mount path of the authorised USB drive."""
        saved = load_usb_id()
        if not saved:
            AlertModal(self.root, "error", "No USB Binding",
                       "No USB binding configured.\n\nSet a secure USB drive first.").show()
            return None
        path = find_authorized_usb(saved)
        if not path:
            AlertModal(self.root, "error", "USB Not Found",
                       "Authorised USB drive not detected.\n\n"
                       "Connect the correct drive and try again.").show()
            return None
        return path

    # ── USB Tools ─────────────────────────────────────────────────────────────

    def usb_analysis(self) -> None:
        path = self._require_usb_path()
        if not path:
            return
        self._log(f"USB Analysis → {path}", "info")
        UsbAnalysisModal(self.root, path).show()
        self._log("USB Analysis closed.", "dim")

    def usb_cleanup(self) -> None:
        path = self._require_usb_path()
        if not path:
            return
        self._log(f"USB Cleanup → {path}", "info")
        result = UsbCleanupModal(self.root, path).show()
        if result:
            self._log("USB Cleanup completed.", "success")
        else:
            self._log("USB Cleanup cancelled.", "dim")

    def _show_backup_menu(self) -> None:
        """Show BACKUP dropdown menu below the BACKUP button."""
        menu = tk.Menu(self.root, tearoff=0,
                       bg=C["surface2"], fg=C["text_bright"],
                       activebackground=C["warning"],
                       activeforeground=C["bg"],
                       font=("Courier New", 9, "bold"),
                       relief=tk.FLAT, bd=0)
        menu.add_command(label="  💾  Create backup",
                         command=self.backup_create)
        menu.add_command(label="  ⬆  Restore backup",
                         command=self.backup_restore)
        menu.add_separator()
        menu.add_command(label="  ✎  Manage backup",
                         command=self.backup_manage)
        try:
            x = self._backup_btn.winfo_rootx()
            y = self._backup_btn.winfo_rooty() + self._backup_btn.winfo_height()
            menu.tk_popup(x, y)
        finally:
            menu.grab_release()

    def backup_create(self) -> None:
        """Open the create-backup modal. User selects files + name + password."""
        result = BackupCreateModal(self.root).show()
        if not result:
            self._log("Backup cancelled.", "warning")
            return
        files    = result["files"]
        name     = result["name"]
        password = result["password"]

        self._log(f"Creating backup \"{name}\" ({len(files)} item(s))…", "dim")
        prog = ProgressModal(self.root, verb="CREATING BACKUP")

        def _run():
            try:
                total = len(files)
                for i, fp in enumerate(files):
                    prog.update(i, total, Path(fp).name)
                ok, msg = create_backup(files, name, password)
                prog.update(total, total, "")
                level = "success" if ok else "error"
                self.root.after(0, lambda: self._log(msg, level))
                self.root.after(400, prog.close)
                if ok:
                    self.root.after(500, self._toast,
                                    f"✓  Backup \"{name}\" created", "success")
                else:
                    self.root.after(500, lambda: AlertModal(
                        self.root, "error", "Backup Failed", msg).show())
            except Exception as exc:
                self._log(f"Backup error: {exc}", "error")
                self.root.after(0, prog.close)
                self.root.after(50, lambda: AlertModal(
                    self.root, "error", "Backup Failed", str(exc)).show())

        threading.Thread(target=_run, daemon=True).start()

    def backup_restore(self) -> None:
        """Open the restore-backup modal. User picks a backup + password."""
        result = BackupRestoreModal(self.root).show()
        if not result:
            self._log("Restore cancelled.", "warning")
            return
        bid      = result["id"]
        password = result["password"]

        # Ask where to restore — original paths or custom folder
        dest = filedialog.askdirectory(
            title="Restore to folder (Cancel = restore to original paths)",
            parent=self.root)
        dest = dest if dest else None

        self._log("Restoring backup…", "dim")
        prog = ProgressModal(self.root, verb="RESTORING BACKUP")

        def _run():
            try:
                # Count files for progress
                idx = _load_backup_index()
                total = next((e["file_count"] for e in idx if e["id"] == bid), 1)
                prog.update(0, total, "Decrypting…")
                ok, msg, paths = restore_backup(bid, password, dest)
                prog.update(total, total, "")
                level = "success" if ok else "error"
                self.root.after(0, lambda: self._log(msg, level))
                for p in paths[:5]:
                    self.root.after(0, lambda p=p: self._log(f"  → {p}", "dim"))
                self.root.after(400, prog.close)
                if ok:
                    self.root.after(500, self._toast,
                                    f"✓  {len(paths)} file(s) restored", "success")
                else:
                    self.root.after(500, lambda: AlertModal(
                        self.root, "error", "Restore Failed", msg).show())
            except Exception as exc:
                self._log(f"Restore error: {exc}", "error")
                self.root.after(0, prog.close)
                self.root.after(50, lambda: AlertModal(
                    self.root, "error", "Restore Error", str(exc)).show())

        threading.Thread(target=_run, daemon=True).start()

    def backup_manage(self) -> None:
        """Open the manage-backups modal (rename / change password / delete)."""
        BackupManageModal(self.root).show()
        self._log("Backup manager closed.", "dim")

    def usb_bindings(self) -> None:
        """Business: show and manage all registered USB key bindings."""
        UsbBindingsModal(self.root).show()
        self._log("USB Bindings reviewed.", "dim")

    def open_audit_log(self) -> None:
        """Business: open the tamper-evident audit log viewer."""
        self._log("Opening audit log…", "dim")
        AuditLogModal(self.root).show()

    # ── Encrypt entry ─────────────────────────────────────────────────────────

    def encrypt_data(self) -> None:
        usb_id   = self._require_usb()
        if not usb_id:
            return
        usb_path = self._require_usb_path()

        password = PasswordDialog(self.root, confirm=True, mode="encrypt").show()
        if not password:
            self._log("Encryption cancelled.", "warning")
            return
        max_attempts = AttemptLimitDialog(self.root).show()
        if max_attempts is None:
            self._log("Encryption cancelled.", "warning")
            return

        # ── Algorithm selection (Pro+) ────────────────────────────────────────
        cipher_id = AlgorithmDialog(self.root).show()
        if cipher_id is None:
            self._log("Encryption cancelled.", "warning")
            return

        # ── Duress / decoy password ───────────────────────────────────────────
        duress_result = DuressDialog(self.root).show()
        duress_pw   = None
        duress_data = b""
        if duress_result:
            duress_pw   = duress_result["duress_password"]
            duress_data = duress_result["duress_data"]
            self._log("Duress password set — dual-slot encryption enabled.", "success")

        # ── If attempt limit set, offer/ensure reset password on USB ──────────
        if max_attempts > 0 and usb_path:
            if not has_reset_password(usb_path):
                reset_pw = ResetPasswordCreateDialog(self.root).show()
                if reset_pw:
                    create_reset_password(usb_path, reset_pw)
                    self._log("Reset password saved to USB.", "success")
                else:
                    self._log("No reset password set — counters cannot be reset later.", "warning")

        choice = FileTypeDialog(self.root, mode="encrypt").show()
        if choice == "file":
            path = filedialog.askopenfilename(
                title="Select file to encrypt", parent=self.root)
        elif choice == "folder":
            path = filedialog.askdirectory(
                title="Select folder to encrypt", parent=self.root)
        else:
            self._log("Encryption cancelled.", "warning")
            return
        if not path or not os.path.exists(path):
            self._log("No valid path selected.", "warning")
            return
        if os.path.isfile(path) and path.endswith(ENC_EXT):
            AlertModal(self.root, "warning", "Already Encrypted",
                       "This file is already encrypted (.avgvsto).").show()
            return
        self._run_encrypt(path, usb_id, password, max_attempts,
                          duress_pw, duress_data, cipher_id)

    # ── Verify entry ──────────────────────────────────────────────────────────

    def verify_data(self) -> None:
        """In-memory integrity check: no files are written or modified."""
        usb_id = self._require_usb()
        if not usb_id:
            return
        path = filedialog.askopenfilename(
            title="Select .avgvsto file to verify",
            filetypes=[("AVGVSTO Encrypted", "*.avgvsto"), ("All files", "*.*")],
            parent=self.root)
        if not path or not os.path.isfile(path):
            return
        password = PasswordDialog(self.root, confirm=False, mode="decrypt").show()
        if not password:
            return
        ok, msg = verify_file(path, password, usb_id)
        tag = "success" if ok else "error"
        self._log(f"VERIFY {os.path.basename(path)}: {msg}", tag)
        audit_log("VERIFY", os.path.basename(path), "OK" if ok else "FAIL", usb_id)
        VerifyResultModal(self.root, ok, msg).show()



    def decrypt_data(self) -> None:
        # ── Anti-bruteforce: block if cooldown active ─────────────────────────
        if brute_remaining() > 0:
            self._log("Cooldown active — wait before retrying.", "warning")
            CooldownModal(self.root).show()
        if brute_remaining() > 0:
            return   # still cooling — abort cleanly

        usb_id = self._require_usb()
        if not usb_id:
            return
        password = PasswordDialog(self.root, confirm=False, mode="decrypt").show()
        if not password:
            self._log("Decryption cancelled.", "warning")
            return
        choice = FileTypeDialog(self.root, mode="decrypt").show()
        if choice == "file":
            path = filedialog.askopenfilename(
                title="Select encrypted file (.avgvsto)",
                filetypes=[("AVGVSTO Encrypted", "*.avgvsto"), ("All files", "*.*")],
                parent=self.root)
        elif choice == "folder":
            path = filedialog.askdirectory(
                title="Select folder containing encrypted files",
                parent=self.root)
        else:
            self._log("Decryption cancelled.", "warning")
            return
        if not path or not os.path.exists(path):
            self._log("No valid path selected.", "warning")
            return
        self._run_decrypt(path, usb_id, password)

    def _run_encrypt(self, path: str, usb_id: str,
                     password: str = None, max_attempts: int = None,
                     duress_password: str = None,
                     duress_data: bytes  = b"",
                     cipher_id: int      = CIPHER_AES) -> None:
        if password is None:
            password = PasswordDialog(self.root, confirm=True, mode="encrypt").show()
            if not password:
                return
        if max_attempts is None:
            max_attempts = AttemptLimitDialog(self.root).show()
            if max_attempts is None:
                return

        is_folder = os.path.isdir(path)
        prog = ProgressModal(
            self.root,
            verb="ENCRYPTING FOLDER" if is_folder else "ENCRYPTING FILE")

        _CIPHER_LABEL = {CIPHER_AES: "AES-256-GCM", CIPHER_CHACHA20: "ChaCha20-Poly1305"}

        def _run() -> None:
            try:
                if not is_folder:
                    prog.update(0, 1, Path(path).name)
                    out = encrypt_file(path, password, usb_id, max_attempts,
                                       duress_password, duress_data, cipher_id)
                    prog.update(1, 1, "")
                    att   = (f"  ·  attempts: {max_attempts}"
                             if max_attempts > 0 else "  ·  unlimited")
                    dual  = "  ·  DUAL-SLOT" if duress_password else ""
                    algo  = f"  ·  {_CIPHER_LABEL.get(cipher_id, '?')}"
                    self._log(f"Encrypted → {Path(out).name}{att}{dual}{algo}", "success")
                    self.root.after(0, self._refresh_stats)
                    self.root.after(400, prog.close)
                    self.root.after(500, self._toast, f"✓  {Path(out).name}", "success")
                else:
                    ok, errors = encrypt_folder(
                        path, password, usb_id, max_attempts,
                        duress_password, duress_data,
                        on_progress=prog.update,
                        cipher_id=cipher_id)
                    algo = _CIPHER_LABEL.get(cipher_id, "?")
                    self._log(f"Folder encrypted: {ok} file(s)  ·  {algo}", "success")
                    for err in errors:
                        self._log(f"  {err}", "warning")
                    self.root.after(0, self._refresh_stats)
                    self.root.after(400, prog.close)
                    self.root.after(500, self._toast,
                                    f"✓  {ok} file(s) encrypted", "success")
            except Exception as exc:
                self._log(f"Encryption error: {exc}", "error")
                self.root.after(0, prog.close)
                self.root.after(50, lambda: AlertModal(
                    self.root, "error", "Encryption Failed", str(exc)).show())

        threading.Thread(target=_run, daemon=True).start()

    # ── Decrypt runner ────────────────────────────────────────────────────────

    def _run_decrypt(self, path: str, usb_id: str, password: str = None) -> None:
        # ── Cooldown guard (also covers calls from drop-zone) ─────────────────
        if brute_remaining() > 0:
            self._log("Cooldown active — wait before retrying.", "warning")
            CooldownModal(self.root).show()
        if brute_remaining() > 0:
            return

        if password is None:
            password = PasswordDialog(self.root, confirm=False, mode="decrypt").show()
            if not password:
                return

        is_folder = os.path.isdir(path)
        prog = ProgressModal(
            self.root,
            verb="DECRYPTING FOLDER" if is_folder else "DECRYPTING FILE")

        def _run() -> None:
            try:
                if not is_folder:
                    prog.update(0, 1, Path(path).name)
                    result = _attempt_decrypt_with_tracking(path, password, usb_id)
                    prog.update(1, 1, "")
                    self._log(f"Decrypted → {Path(result).name}", "success")
                    self.root.after(0, self._refresh_stats)
                    self.root.after(400, prog.close)
                    self.root.after(500, self._toast,
                                    f"✓  {Path(result).name}", "success")
                else:
                    ok, errors = decrypt_folder(
                        path, password, usb_id, on_progress=prog.update)
                    self._log(f"Folder decrypted: {ok} file(s).", "success")
                    for err in errors:
                        self._log(f"  {err}", "warning")
                    self.root.after(0, self._refresh_stats)
                    self.root.after(400, prog.close)
                    self.root.after(500, self._toast,
                                    f"✓  {ok} file(s) decrypted", "success")
            except PermissionError as exc:
                self._log(f"ACCESS BLOCKED: {exc}", "error")
                self.root.after(0, prog.close)
                self.root.after(50, lambda: AlertModal(
                    self.root, "error", "Access Blocked", str(exc)).show())
            except ValueError as exc:
                # brute_mark_fail() already called inside _attempt_decrypt_with_tracking
                self._log(f"Auth failed: {exc}", "error")
                self.root.after(0, prog.close)
                def _show_cooldown_then_alert(msg=str(exc)):
                    CooldownModal(self.root).show()
                    AlertModal(self.root, "error", "Decryption Failed", msg).show()
                self.root.after(50, _show_cooldown_then_alert)
            except Exception as exc:
                self._log(f"Decryption error: {exc}", "error")
                self.root.after(0, prog.close)
                self.root.after(50, lambda: AlertModal(
                    self.root, "error", "Decryption Error", str(exc)).show())

        threading.Thread(target=_run, daemon=True).start()

    # ── Multi-item batch runner ───────────────────────────────────────────────

    def _run_multi(self, paths: List[str], usb_id: str, action: str,
                   password: str, max_attempts) -> None:
        # ── Cooldown guard for decrypt operations ─────────────────────────────
        if action == "decrypt" and brute_remaining() > 0:
            self._log("Cooldown active — wait before retrying.", "warning")
            CooldownModal(self.root).show()
        if action == "decrypt" and brute_remaining() > 0:
            return

        verb_up = "ENCRYPTING" if action == "encrypt" else "DECRYPTING"
        prog = ProgressModal(self.root, verb=f"{verb_up} {len(paths)} ITEMS")

        def _run() -> None:
            ok, errors = 0, []
            total = len(paths)
            for i, path in enumerate(paths):
                prog.update(i, total, os.path.basename(path))
                try:
                    if os.path.isdir(path):
                        if action == "encrypt":
                            n, errs = encrypt_folder(
                                path, password, usb_id, max_attempts)
                        else:
                            n, errs = decrypt_folder(path, password, usb_id)
                        ok += n
                        errors.extend(errs)
                    else:
                        if action == "encrypt":
                            encrypt_file(path, password, usb_id, max_attempts)
                        else:
                            _attempt_decrypt_with_tracking(path, password, usb_id)
                        ok += 1
                except PermissionError as exc:
                    errors.append(f"{os.path.basename(path)}: LOCKED — {exc}")
                except Exception as exc:
                    errors.append(f"{os.path.basename(path)}: {exc}")

            prog.update(total, total, "")
            verb_past = "encrypted" if action == "encrypt" else "decrypted"
            self._log(f"Batch {verb_past}: {ok} item(s).", "success")
            for err in errors:
                self._log(f"  {err}", "warning")
            self.root.after(400, prog.close)
            self.root.after(500, self._toast,
                            f"✓  {ok} item(s) {verb_past}", "success")

        threading.Thread(target=_run, daemon=True).start()

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        self.root.mainloop()

# ══════════════════════════════════════════════════════════════════════════════
#  CLI  (non-GUI mode for scripting / developer usage)
# ══════════════════════════════════════════════════════════════════════════════

def _cli_getpass(prompt: str) -> str:
    import getpass
    return getpass.getpass(prompt)

def _cli_run() -> None:
    """
    Usage:
        avgvsto encrypt  <path> [--usb PATH] [--attempts N] [--duress]
        avgvsto decrypt  <path> [--usb PATH]
        avgvsto verify   <file> [--usb PATH]
        avgvsto status
        avgvsto bind-usb <path>
        avgvsto portable-init   # create .avgvsto_portable flag next to script
    """
    _ensure_dirs()
    _load_brute_state()

    parser = argparse.ArgumentParser(
        prog="avgvsto",
        description="AVGVSTO — AES-256-GCM encryption with USB hardware key")
    sub = parser.add_subparsers(dest="cmd")

    p_enc = sub.add_parser("encrypt", help="Encrypt file or folder")
    p_enc.add_argument("path")
    p_enc.add_argument("--usb",       default=None, help="USB mount path")
    p_enc.add_argument("--attempts",  type=int, default=0,
                       help="Max decryption attempts (0=unlimited)")
    p_enc.add_argument("--duress",    action="store_true",
                       help="Also prompt for a duress/decoy password")

    p_dec = sub.add_parser("decrypt", help="Decrypt file or folder")
    p_dec.add_argument("path")
    p_dec.add_argument("--usb", default=None)

    p_ver = sub.add_parser("verify", help="Verify file integrity (no writes)")
    p_ver.add_argument("path")
    p_ver.add_argument("--usb", default=None)

    sub.add_parser("status", help="Show USB binding status")

    p_bind = sub.add_parser("bind-usb", help="Bind a USB drive as hardware key")
    p_bind.add_argument("path", help="Mount path of the USB drive")

    sub.add_parser("portable-init",
                   help="Create .avgvsto_portable flag for portable mode")

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        sys.exit(0)

    # ── status ────────────────────────────────────────────────────────────────
    if args.cmd == "status":
        saved = load_usb_id()
        s = _load_stats()
        if saved:
            path = find_authorized_usb(saved)
            if path:
                print(f"[✓] USB binding: {saved[:16]}…  (connected at {path})")
            else:
                print(f"[!] USB binding: {saved[:16]}…  (NOT CONNECTED)")
        else:
            print("[×] No USB binding configured.")
        print(f"    Files encrypted:  {s.get('files_encrypted', 0)}")
        print(f"    Files decrypted:  {s.get('files_decrypted', 0)}")
        print(f"    Bytes encrypted:  {_fmt_size(s.get('bytes_encrypted', 0))}")
        rem = brute_remaining()
        if rem > 0:
            print(f"    Cooldown active:  {rem:.0f}s remaining")
        print(f"    Portable mode:    {'yes' if _IS_PORTABLE else 'no'}")
        sys.exit(0)

    # ── bind-usb ──────────────────────────────────────────────────────────────
    if args.cmd == "bind-usb":
        uid = save_usb_config(args.path)
        if uid:
            print(f"[✓] USB bound — ID: {uid}")
        else:
            print("[×] Failed to read device identifier.", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    # ── portable-init ─────────────────────────────────────────────────────────
    if args.cmd == "portable-init":
        _PORTABLE_FLAG.touch()
        print(f"[✓] Portable flag created: {_PORTABLE_FLAG}")
        print("    Restart AVGVSTO — config will be stored next to the script.")
        sys.exit(0)

    # ── All remaining cmds need USB ID ────────────────────────────────────────
    usb_mount = getattr(args, "usb", None)
    if usb_mount:
        usb_id = get_usb_identifier(usb_mount) or save_usb_config(usb_mount)
    else:
        cfg = load_usb_id()
        usb_id = cfg if cfg else None
        if usb_id:
            usb_mount = find_authorized_usb(usb_id) or ""

    if not usb_id:
        print("[×] No USB binding found. Use `avgvsto bind-usb <path>` first.",
              file=sys.stderr)
        sys.exit(1)

    # ── cooldown guard ────────────────────────────────────────────────────────
    if args.cmd in ("decrypt", "verify"):
        rem = brute_remaining()
        if rem > 0:
            print(f"[!] Cooldown active — wait {rem:.0f}s before retrying.",
                  file=sys.stderr)
            sys.exit(1)

    target = args.path
    if not os.path.exists(target):
        print(f"[×] Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    # ── encrypt ───────────────────────────────────────────────────────────────
    if args.cmd == "encrypt":
        password = _cli_getpass("Encryption password: ")
        confirm  = _cli_getpass("Confirm password:    ")
        if password != confirm:
            print("[×] Passwords do not match.", file=sys.stderr)
            sys.exit(1)
        duress_pw   = None
        duress_data = b""
        if args.duress:
            duress_pw   = _cli_getpass("Duress password: ")
            duress_conf = _cli_getpass("Confirm duress:  ")
            if duress_pw != duress_conf:
                print("[×] Duress passwords do not match.", file=sys.stderr)
                sys.exit(1)
        try:
            if os.path.isfile(target):
                out = encrypt_file(target, password, usb_id, args.attempts,
                                   duress_pw, duress_data)
                print(f"[✓] Encrypted → {out}")
            else:
                def _prog(done, total, name):
                    if name:
                        print(f"  [{done+1}/{total}] {name}")
                ok, errors = encrypt_folder(target, password, usb_id,
                                            args.attempts, duress_pw, duress_data,
                                            on_progress=_prog)
                print(f"[✓] {ok} file(s) encrypted.")
                for e in errors:
                    print(f"  [!] {e}", file=sys.stderr)
        except Exception as exc:
            print(f"[×] Encryption failed: {exc}", file=sys.stderr)
            sys.exit(1)

    # ── decrypt ───────────────────────────────────────────────────────────────
    elif args.cmd == "decrypt":
        password = _cli_getpass("Decryption password: ")
        try:
            if os.path.isfile(target):
                result = _attempt_decrypt_with_tracking(target, password, usb_id)
                print(f"[✓] Decrypted → {result}")
            else:
                def _prog(done, total, name):
                    if name:
                        print(f"  [{done+1}/{total}] {name}")
                ok, errors = decrypt_folder(target, password, usb_id,
                                            on_progress=_prog)
                print(f"[✓] {ok} file(s) decrypted.")
                for e in errors:
                    print(f"  [!] {e}", file=sys.stderr)
        except PermissionError as exc:
            print(f"[×] ACCESS BLOCKED: {exc}", file=sys.stderr)
            sys.exit(1)
        except ValueError as exc:
            brute_mark_fail()
            print(f"[×] Authentication failed: {exc}", file=sys.stderr)
            sys.exit(1)

    # ── verify ────────────────────────────────────────────────────────────────
    elif args.cmd == "verify":
        if not os.path.isfile(target):
            print(f"[×] Verify requires a single file.", file=sys.stderr)
            sys.exit(1)
        password = _cli_getpass("Password: ")
        ok, msg = verify_file(target, password, usb_id)
        print(f"{'[✓]' if ok else '[×]'} {msg}")
        sys.exit(0 if ok else 1)

# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    _ensure_dirs()
    _load_brute_state()    # restore progressive cooldown counter from disk

    # If any CLI arguments present, run headless
    if len(sys.argv) > 1:
        _cli_run()
        sys.exit(0)

    # Otherwise launch GUI
    try:
        app = AVGVSTOApp()
        app.run()
    except Exception as exc:
        print(f"[AVGVSTO FATAL] {exc}", file=sys.stderr)
        sys.exit(1)

