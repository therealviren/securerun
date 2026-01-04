#!/usr/bin/env python3
# sr.py
"""
License & Disclaimer
Copyright © 2025 Viren

This software is provided "as is", without any warranty, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.

By using this software, you agree that Viren is not responsible for any direct or indirect damages, loss of data, profits, or other consequences arising from:
- Misuse of the software
- Criminal activity, hacking, or any illegal use
- Modifications or derivative works
- Software bugs, failures, or security breaches

This software may only be used for legitimate purposes. Redistribution, modification, or claiming the code as your own is strictly prohibited. All rights remain with Viren.

Use at your own risk.
"""

"""
READ LICENSE AND README.MD
"""

import os
import sys
import json
import time
import base64
import getpass
import hashlib
import argparse
import traceback
import hmac
import shutil
import gc
import zipfile
import importlib.util
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from colorama import init, Fore, Style

init(autoreset=True)

VERSION = "0.1.0"

def _user_data_dir():
    if os.name == "nt":
        return os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "sr")
    else:
        return os.path.join(os.path.expanduser("~/.local/share"), "sr")

BASE_DIR = _user_data_dir()
PLUGIN_DIR = os.path.join(BASE_DIR, "plugins")
LOCKED_DIR = os.path.join(BASE_DIR, "locked")
PLUGIN_SETTINGS_DIR = os.path.join(PLUGIN_DIR, "settings")
PLUGIN_SETTINGS_FILE = os.path.join(PLUGIN_SETTINGS_DIR, "plugins.json")

GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RED = Fore.RED
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT

_runtime_cache = {}
_PLUGIN_COMMANDS = {}
_PBKDF2_ITER = 5_000_000
_DK_LEN = 32

def _ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _info(msg):
    print(f"{BOLD}{GREEN}[{_ts()}] {msg}{RESET}")

def _warn(msg):
    print(f"{BOLD}{YELLOW}[{_ts()}] {msg}{RESET}")

def _err(msg):
    print(f"{BOLD}{RED}[{_ts()}] {msg}{RESET}")
    
def _ensure_dirs():
    os.makedirs(LOCKED_DIR, exist_ok=True)

def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def _sr_path(label: str) -> str:
    safe = label.replace("/", "_").replace("..", "_").replace(" ", "_")
    return os.path.join(LOCKED_DIR, f"{safe}.sr")

def _derive_key(password: bytes, salt: bytes, iterations: int = _PBKDF2_ITER) -> bytes:
    if iterations <= 0:
        raise ValueError("Invalid PBKDF2 iteration count")

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password,
        salt,
        iterations,
        dklen=32
    )
    return key

def _chacha_encrypt(plain: bytes, key: bytes):
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    ct = cipher.encrypt(nonce, plain, None)
    return nonce, ct

def _chacha_decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, None)    

def _zero_bytes(b):
    try:
        if isinstance(b, bytearray):
            for i in range(len(b)):
                b[i] = 0
    except Exception:
        pass

def setup():
    _ensure_dirs()
    _info(f"SR setup done. Version {VERSION}")

def register_command(name, help, handler):
    if not name.isidentifier():
        raise ValueError("Invalid command name")
    if name in _PLUGIN_COMMANDS:
        raise ValueError("Command already exists")
    _PLUGIN_COMMANDS[name] = {
        "help": help,
        "handler": handler
    }

def load_plugins():
    os.makedirs(PLUGIN_DIR, exist_ok=True)
    settings = _load_plugin_settings()

    for fname in os.listdir(PLUGIN_DIR):
        if not fname.endswith(".py"):
            continue

        name = fname[:-3]
        if not _is_plugin_enabled(name):
            _warn(f"Plugin disabled: {name}")
            continue

        path = os.path.join(PLUGIN_DIR, fname)
        spec = importlib.util.spec_from_file_location(f"sr_plugin_{name}", path)
        mod = importlib.util.module_from_spec(spec)

        try:
            spec.loader.exec_module(mod)
            if hasattr(mod, "register"):
                mod.register(sys.modules[__name__])
                _info(f"Loaded plugin: {name}")
        except Exception as e:
            _err(f"Plugin {name} failed: {e}")
            
def _load_plugin_settings():
    os.makedirs(PLUGIN_SETTINGS_DIR, exist_ok=True)
    if not os.path.isfile(PLUGIN_SETTINGS_FILE):
        return {"enabled": {}}
    try:
        with open(PLUGIN_SETTINGS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"enabled": {}}

def _save_plugin_settings(data):
    os.makedirs(PLUGIN_SETTINGS_DIR, exist_ok=True)
    tmp = PLUGIN_SETTINGS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, PLUGIN_SETTINGS_FILE)

def _is_plugin_enabled(name: str) -> bool:
    settings = _load_plugin_settings()
    return settings.get("enabled", {}).get(name, True)
    
def logo():
    print(f"""{GREEN}{BOLD}
  ███████╗██████╗ 
  ██╔════╝██╔══██╗
  ███████╗██████╔╝
  ╚════██║██╔══██╗
  ███████║██║  ██║
  ╚══════╝╚═╝  ╚═╝
{RESET}""")

def logo_with_text():
    print(f"""{GREEN}{BOLD}
  ███████╗██████╗ 
  ██╔════╝██╔══██╗
  ███████╗██████╔╝
  ╚════██║██╔══██╗
  ███████║██║  ██║
  ╚══════╝╚═╝  ╚═╝
  Secure Run
{RESET}""")

def logo_with_version():
    print(f"""{GREEN}{BOLD}
  ███████╗██████╗ 
  ██╔════╝██╔══██╗
  ███████╗██████╔╝
  ╚════██║██╔══██╗
  ███████║██║  ██║
  ╚══════╝╚═╝  ╚═╝
  Secure Run {VERSION}
{RESET}""")

def cls():
    os.system("cls" if os.name == "nt" else "clear")
    logo()
    
def lock(label: str, filepath: str, password: str = None, pbkdf2_iter: int = _PBKDF2_ITER):
    if not filepath.endswith(".py"):
        _err("Only .py files are allowed to be locked.")
        raise ValueError("Only .py files are allowed")

    if password is None:
        password = getpass.getpass("Enter password to lock: ")

    if not os.path.isfile(filepath):
        _err("Input file not found.")
        raise FileNotFoundError(filepath)

    with open(filepath, "rb") as f:
        raw = f.read()

    file_hash = _sha256_bytes(raw)
    salt = os.urandom(16)
    key = _derive_key(password.encode("utf-8"), salt, int(pbkdf2_iter))

    nonce, ct = _chacha_encrypt(raw, key)
    _zero_bytes(bytearray(key))

    payload = {
        "meta": {
            "filename": os.path.basename(filepath),
            "locked_at": _ts(),
            "method": "chacha20-poly1305",
            "pbkdf2_iter": int(pbkdf2_iter),
        },
        "data": {
            "file_hash": file_hash,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode()
        }
    }

    path = _sr_path(label)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, path)
    _zero_bytes(bytearray(ct))
    del raw
    gc.collect()
    _info(f"Locked {filepath} as '{label}' -> {path}")
    return path

def _decrypt_payload(payload: dict, password: str) -> bytes:
    try:
        data = payload["data"]
        salt = base64.b64decode(data["salt"])
        nonce = base64.b64decode(data["nonce"])
        ct = base64.b64decode(data["ciphertext"])
    except Exception:
        raise ValueError("Malformed sr file")

    iterations = int(payload["meta"].get("pbkdf2_iter", _PBKDF2_ITER))
    key = _derive_key(password.encode("utf-8"), salt, iterations)

    try:
        plain = _chacha_decrypt(ct, nonce, key)
    except Exception:
        _zero_bytes(bytearray(key))
        raise RuntimeError("Decryption failed (wrong password or corrupted data)")

    _zero_bytes(bytearray(key))

    expected_hash = data.get("file_hash")
    if expected_hash and not hmac.compare_digest(_sha256_bytes(plain), expected_hash):
        _zero_bytes(bytearray(plain))
        raise ValueError("Integrity check failed")

    return plain

def get_runtime(label: str, password: str = None) -> bytes:
    path = _sr_path(label)
    if not os.path.isfile(path):
        _err("Locked item not found.")
        raise FileNotFoundError(path)

    if password is None:
        password = getpass.getpass(f"Enter password for '{label}': ")

    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    plain = _decrypt_payload(payload, password)
    _runtime_cache[label] = plain[:]
    _info(f"Decrypted '{label}' into runtime cache only (no disk write).")
    return _runtime_cache[label]
    
def run(label: str, password: str = None, show_output: bool = True):
    path = _sr_path(label)
    if not os.path.isfile(path):
        _err("Locked item not found.")
        raise FileNotFoundError(path)

    plain = _runtime_cache.get(label)
    if plain is None:
        if password is None:
            password = getpass.getpass(f"Enter password to run '{label}': ")
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        plain = _decrypt_payload(payload, password)

    try:
        src = plain.decode("utf-8", errors="replace")
    except Exception:
        _zero_bytes(bytearray(plain))
        raise RuntimeError("Failed to decode script")

    filename = os.path.basename(label) + ".py"
    header = f"{BOLD}{GREEN}Running ({label}) - {filename}...{RESET}"
    if show_output:
        print(header)
    start = time.time()

    try:
        code_obj = compile(src, filename, "exec")
        g = {"__name__": "__main__", "__file__": filename}
        try:
            exec(code_obj, g, g)
        except SystemExit:
            _warn("Script called exit().")
        except Exception as e:
            _err(f"Runtime error in decrypted script: {e}")
            _err(traceback.format_exc())
            raise
    finally:
        elapsed = time.time() - start
        _info(f"Finished running {label} in {elapsed:.2f}s.")
        try:
            _zero_bytes(bytearray(plain))
        except Exception:
            pass
        del src, code_obj, plain
        _runtime_cache.pop(label, None)
        gc.collect()

    return True
    
def get(label: str, password: str = None) -> bytes:
    path = _sr_path(label)
    if not os.path.isfile(path):
        _err("Locked item not found.")
        raise FileNotFoundError(path)

    if password is None:
        password = getpass.getpass("Enter password to get file: ")

    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    plain = _decrypt_payload(payload, password)

    filename = payload.get("meta", {}).get("filename") or f"{label}.py"
    if not filename.endswith(".py"):
        _zero_bytes(bytearray(plain))
        raise ValueError("Stored filename is not a .py file; refusing to write to disk.")

    _runtime_cache[label] = plain[:]
    _info(f"Decrypted '{label}' into runtime cache only (no disk write). Filename: {filename}")
    return _runtime_cache[label]
    
def delete(label: str):
    path = _sr_path(label)
    if os.path.isfile(path):
        try:
            os.remove(path)
            _info(f"Deleted locked file: {path}")
        except Exception as e:
            _err("Failed to delete file: " + str(e))
            raise
    else:
        _warn("Item not found; nothing to delete.")
    _runtime_cache.pop(label, None)

def flush():
    for k, v in list(_runtime_cache.items()):
        try:
            _zero_bytes(bytearray(v))
        except Exception:
            pass
        _runtime_cache.pop(k, None)
    _info("Runtime cache flushed. All decrypted bytes removed from memory cache (best-effort).")
    gc.collect()

def reset(confirm: bool = False):
    if not confirm:
        _warn("Call reset(confirm=True) to actually wipe all locked data.")
        return

    if os.path.isdir(LOCKED_DIR):
        for fname in os.listdir(LOCKED_DIR):
            if fname.endswith(".sr"):
                try:
                    os.remove(os.path.join(LOCKED_DIR, fname))
                except Exception:
                    pass

    if os.path.isdir(BASE_DIR):
        for fname in os.listdir(BASE_DIR):
            if fname.endswith(".py"):
                try:
                    os.remove(os.path.join(BASE_DIR, fname))
                except Exception:
                    pass

    if os.path.isdir(PLUGIN_DIR):
        for fname in os.listdir(PLUGIN_DIR):
            if fname.endswith(".py"):
                try:
                    os.remove(os.path.join(PLUGIN_DIR, fname))
                except Exception:
                    pass

    if os.path.isdir(PLUGIN_SETTINGS_DIR):
        try:
            shutil.rmtree(PLUGIN_SETTINGS_DIR)
        except Exception:
            pass

    bundle_dir = os.path.join(BASE_DIR, "bundles")
    if os.path.isdir(bundle_dir):
        for fname in os.listdir(bundle_dir):
            if fname.endswith(".json"):
                try:
                    os.remove(os.path.join(bundle_dir, fname))
                except Exception:
                    pass

    _runtime_cache.clear()
    _info("FULL reset: removed .sr files, written .py files, plugins, plugin settings, bundles, and cleared memory cache.")
    gc.collect()
    
def export_sr(label: str, out_path: str = None):
    path = _sr_path(label)
    if not os.path.isfile(path):
        _err("Locked item not found.")
        raise FileNotFoundError(path)

    if out_path is None:
        out_path = os.path.join(os.getcwd(), os.path.basename(path))

    tmp = out_path + ".tmp"
    try:
        with open(path, "rb") as f_in:
            data = f_in.read()
        with open(tmp, "wb") as f_out:
            f_out.write(data)
            f_out.flush()
            os.fsync(f_out.fileno())
        os.replace(tmp, out_path)
        _info(f"Exported .sr file to: {out_path}")
    except Exception as e:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        _err("Failed to export .sr file: " + str(e))
        raise
        
def import_sr(file_path: str, label: str = None):
    if not os.path.isfile(file_path):
        _err("Source .sr file not found.")
        raise FileNotFoundError(file_path)

    if label is None:
        label = os.path.splitext(os.path.basename(file_path))[0]

    dest_path = _sr_path(label)
    tmp = dest_path + ".tmp"
    try:
        with open(file_path, "rb") as f_in:
            data = f_in.read()
        with open(tmp, "wb") as f_out:
            f_out.write(data)
            f_out.flush()
            os.fsync(f_out.fileno())
        os.replace(tmp, dest_path)
        _info(f"Imported .sr file as '{label}' -> {dest_path}")
    except Exception as e:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        _err("Failed to import .sr file: " + str(e))
        raise       

def info(label: str, *, as_json=False, show_hash=False, show_path=False, quiet=False):
    path = _sr_path(label)
    if not os.path.isfile(path):
        _err("Locked item not found.")
        return

    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    meta = payload.get("meta", {})
    data = payload.get("data", {})

    if as_json:
        print(json.dumps(payload, indent=2))
        return

    if show_path:
        print(f"path: {path}")

    if quiet:
        print(f"label: {label}")
        print(f"method: {meta.get('method')}")
        print(f"locked_at: {meta.get('locked_at')}")
        return

    print(f"{BOLD}label:{RESET} {label}")
    for k in ("filename", "locked_at", "method", "pbkdf2_iter"):
        if k in meta:
            print(f"{k}: {meta[k]}")

    if show_hash and "file_hash" in data:
        print(f"file_hash: {data['file_hash']}")
        
def install_plugin(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(file_path)

    os.makedirs(PLUGIN_DIR, exist_ok=True)
    name = os.path.basename(file_path)

    if not name.endswith(".py"):
        raise ValueError("Plugin must be .py")

    dest = os.path.join(PLUGIN_DIR, name)
    shutil.copy2(file_path, dest)

    settings = _load_plugin_settings()
    settings.setdefault("enabled", {})[name[:-3]] = True
    _save_plugin_settings(settings)

    _info(f"Installed and enabled plugin: {name}")
    
def uninstall_plugin(name: str):
    path = os.path.join(PLUGIN_DIR, name + ".py")
    if os.path.isfile(path):
        try:
            os.remove(path)
            _info(f"Removed plugin file: {name}")
        except Exception as e:
            _err(f"Failed to delete plugin file: {e}")
            raise
    else:
        _warn(f"Plugin file not found: {name}")

    settings = _load_plugin_settings()
    if "enabled" in settings and name in settings["enabled"]:
        settings["enabled"].pop(name)
        _save_plugin_settings(settings)
        _info(f"Removed plugin from settings: {name}")
        
def plugin_enable(name: str):
    settings = _load_plugin_settings()
    settings.setdefault("enabled", {})[name] = True
    _save_plugin_settings(settings)
    _info(f"Plugin enabled: {name}")

def plugin_disable(name: str):
    settings = _load_plugin_settings()
    settings.setdefault("enabled", {})[name] = False
    _save_plugin_settings(settings)
    _info(f"Plugin disabled: {name}")

def plugin_enable_all():
    settings = _load_plugin_settings()
    settings["enabled"] = {}

    for f in os.listdir(PLUGIN_DIR):
        if f.endswith(".py"):
            name = f[:-3]
            settings["enabled"][name] = True

    _save_plugin_settings(settings)
    _info("All plugins enabled")

def plugin_disable_all():
    settings = _load_plugin_settings()
    settings["enabled"] = {}

    for f in os.listdir(PLUGIN_DIR):
        if f.endswith(".py"):
            name = f[:-3]
            settings["enabled"][name] = False

    _save_plugin_settings(settings)
    _info("All plugins disabled")
    
def relock(label: str, old_password: str = None, new_password: str = None, pbkdf2_iter: int = _PBKDF2_ITER):
    path = _sr_path(label)
    if not os.path.isfile(path):
        _err("Locked item not found.")
        raise FileNotFoundError(path)

    if old_password is None:
        old_password = getpass.getpass("Enter CURRENT password: ")

    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    plain = _decrypt_payload(payload, old_password)

    if new_password is None:
        new_password = getpass.getpass("Enter NEW password: ")
        confirm = getpass.getpass("Confirm NEW password: ")
        if new_password != confirm:
            _zero_bytes(bytearray(plain))
            raise ValueError("Passwords do not match")

    new_hash = _sha256_bytes(plain)

    salt = os.urandom(16)
    key = _derive_key(new_password.encode(), salt, int(pbkdf2_iter))
    nonce, ct = _chacha_encrypt(plain, key)

    _zero_bytes(bytearray(key))
    _zero_bytes(bytearray(plain))

    payload["meta"]["locked_at"] = _ts()
    payload["meta"]["pbkdf2_iter"] = int(pbkdf2_iter)
    payload["data"] = {
        "file_hash": new_hash,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, path)

    _zero_bytes(bytearray(ct))
    gc.collect()
    _info(f"Password changed for '{label}'")
    
def list_labels(as_json: bool = False):
    os.makedirs(LOCKED_DIR, exist_ok=True)
    labels = [f[:-3] for f in sorted(os.listdir(LOCKED_DIR)) if f.endswith(".sr")]
    if as_json:
        print(json.dumps(labels, indent=2))
    else:
        for lbl in labels:
            print(lbl)
    return labels
    
def create_bundle(name: str, labels: list[str]):
    bundle_dir = os.path.join(BASE_DIR, "bundles")
    os.makedirs(bundle_dir, exist_ok=True)
    bundle_path = os.path.join(bundle_dir, name + ".json")
    with open(bundle_path, "w") as f:
        json.dump(labels, f)
    _info(f"Bundle '{name}' created with labels: {labels}")

def run_bundle(name: str):
    bundle_dir = os.path.join(BASE_DIR, "bundles")
    bundle_path = os.path.join(bundle_dir, name + ".json")
    if not os.path.isfile(bundle_path):
        raise FileNotFoundError(f"Bundle '{name}' not found")
    with open(bundle_path, "r") as f:
        labels = json.load(f)
    for lbl in labels:
        run(lbl)

def delete_bundle(name: str):
    bundle_dir = os.path.join(BASE_DIR, "bundles")
    bundle_path = os.path.join(bundle_dir, name + ".json")
    if os.path.isfile(bundle_path):
        os.remove(bundle_path)
        _info(f"Bundle '{name}' deleted")

def backup(out_path: str = None) -> str:
    if out_path is None:
        out_path = os.path.join(
            os.getcwd(),
            f"sr_backup_{int(time.time())}.zip"
        )

    try:
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
            if os.path.isdir(LOCKED_DIR):
                for f in os.listdir(LOCKED_DIR):
                    if f.endswith(".sr"):
                        p = os.path.join(LOCKED_DIR, f)
                        z.write(p, arcname=f"locked/{f}")

            if os.path.isdir(PLUGIN_DIR):
                for f in os.listdir(PLUGIN_DIR):
                    if f.endswith(".py"):
                        p = os.path.join(PLUGIN_DIR, f)
                        z.write(p, arcname=f"plugins/{f}")

            if os.path.isfile(PLUGIN_SETTINGS_FILE):
                z.write(
                    PLUGIN_SETTINGS_FILE,
                    arcname="plugins/settings/plugins.json"
                )

            bundle_dir = os.path.join(BASE_DIR, "bundles")
            if os.path.isdir(bundle_dir):
                for f in os.listdir(bundle_dir):
                    if f.endswith(".json"):
                        p = os.path.join(bundle_dir, f)
                        z.write(p, arcname=f"bundles/{f}")

        _info(f"FULL backup created: {out_path}")
        return out_path

    except Exception as e:
        _err(f"FULL backup failed: {e}")
        raise

def restore(zip_path: str):
    if not os.path.isfile(zip_path):
        raise FileNotFoundError(zip_path)

    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            for m in z.namelist():
                dest = os.path.join(BASE_DIR, m)

                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with z.open(m) as src, open(dest, "wb") as out:
                    out.write(src.read())

        _info("FULL restore completed.")
    except Exception as e:
        _err(f"FULL restore failed: {e}")
        raise

def rename(label: str, new_label: str) -> str:
    old_path = _sr_path(label)
    new_path = _sr_path(new_label)
    if not os.path.isfile(old_path):
        _err(f"Locked item '{label}' not found.")
        raise FileNotFoundError(old_path)
    if os.path.isfile(new_path):
        _err(f"Target label '{new_label}' already exists.")
        raise FileExistsError(new_path)
    try:
        os.rename(old_path, new_path)
        _info(f"'{label}' renamed to '{new_label}'")
        if label in _runtime_cache:
            _runtime_cache[new_label] = _runtime_cache.pop(label)
        return new_path
    except Exception as e:
        _err(f"Rename failed for '{label}': {e}")
        raise

def clone(label: str, new_label: str) -> str:
    path = _sr_path(label)
    new_path = _sr_path(new_label)
    if not os.path.isfile(path):
        _err(f"Locked item '{label}' not found.")
        raise FileNotFoundError(path)
    if os.path.isfile(new_path):
        _err(f"Target label '{new_label}' already exists.")
        raise FileExistsError(new_path)
    try:
        shutil.copy2(path, new_path)
        _info(f"'{label}' cloned to '{new_label}' -> {new_path}")
        if label in _runtime_cache:
            _runtime_cache[new_label] = _runtime_cache[label][:]
        return new_path
    except Exception as e:
        _err(f"Clone failed for '{label}': {e}")
        raise        

def verify(label: str, password: str = None) -> bool:
    path = _sr_path(label)
    if not os.path.isfile(path):
        _err("Locked item not found.")
        return False

    if password is None:
        password = getpass.getpass(f"Enter password for '{label}': ")

    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)

        plain = _decrypt_payload(payload, password)

        try:
            _zero_bytes(bytearray(plain))
        except Exception:
            pass
        del plain
        gc.collect()

        _info("Password correct.")
        return True

    except Exception:
        time.sleep(1.5)
        _warn("Password incorrect.")
        return False
        
def run_ghost(label: str, password: str = None):
    path = _sr_path(label)
    if not os.path.isfile(path):
        _err("Locked item not found.")
        raise FileNotFoundError(path)

    plain = _runtime_cache.get(label)
    if plain is None:
        if password is None:
            password = getpass.getpass(f"Enter password to run '{label}': ")
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        plain = _decrypt_payload(payload, password)

    try:
        src = plain.decode("utf-8", errors="replace")
    finally:
        _zero_bytes(bytearray(plain))

    filename = os.path.basename(label) + ".py"
    code_obj = compile(src, filename, "exec")
    g = {"__name__": "__main__", "__file__": filename}

    try:
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                exec(code_obj, g, g)
            except SystemExit:
                _warn("Script called exit()")
            except Exception as e:
                _err(f"Runtime error in ghost-run: {e}")
                raise
    finally:
        _runtime_cache.pop(label, None)
        gc.collect()

    _info(f"Ghost-run finished for '{label}'")
    return True
    
def exit_sr(force: bool = False):
    _info(f"Exiting (force={force})")
    flush() 
    if force:
        os._exit(1)
    else:
        sys.exit(0)

# -----------------------
# CLI wrapper
# -----------------------
def _cli():
    setup()
    load_plugins()

    parser = argparse.ArgumentParser(
        prog="sr",
        description="Secure Run (SR) - Encrypted Python execution environment"
    )
    sub = parser.add_subparsers(dest="cmd")

    # -----------------
    # Core commands
    # -----------------

    p_lock = sub.add_parser("lock", help="Encrypt and lock a Python file")
    p_lock.add_argument("label")
    p_lock.add_argument("file")
    p_lock.add_argument("--iter", type=int, default=_PBKDF2_ITER)

    p_run = sub.add_parser("run", help="Run a locked Python script")
    p_run.add_argument("label")

    p_get = sub.add_parser("get", help="Decrypt script into runtime memory")
    p_get.add_argument("label")

    p_relock = sub.add_parser("relock", help="Change password for locked script")
    p_relock.add_argument("label")
    p_relock.add_argument("--iter", type=int, default=_PBKDF2_ITER)

    p_delete = sub.add_parser("delete", help="Delete a locked script")
    p_delete.add_argument("label")

    sub.add_parser("flush", help="Flush runtime cache")

    p_reset = sub.add_parser("reset", help="FULL reset (all data)")
    p_reset.add_argument("--confirm", action="store_true")
    
    p_ghost = sub.add_parser("ghost-run", help="Run a locked Python script silently")
    p_ghost.add_argument("label")
    # -----------------
    # Import / Export
    # -----------------

    p_export = sub.add_parser("export", help="Export a .sr file")
    p_export.add_argument("label")
    p_export.add_argument("--out")

    p_import = sub.add_parser("import", help="Import a .sr file")
    p_import.add_argument("file")
    p_import.add_argument("--label")

    # -----------------
    # Info / labels
    # -----------------

    p_info = sub.add_parser("info", help="Show script metadata")
    p_info.add_argument("label")
    p_info.add_argument("--json", action="store_true")
    p_info.add_argument("--hash", action="store_true")
    p_info.add_argument("--path", action="store_true")
    p_info.add_argument("--quiet", action="store_true")

    sub.add_parser("labels", help="List all locked labels")

    # -----------------
    # Rename / Clone
    # -----------------

    p_rename = sub.add_parser("rename", help="Rename a locked script")
    p_rename.add_argument("label")
    p_rename.add_argument("new_label")

    p_clone = sub.add_parser("clone", help="Clone a locked script")
    p_clone.add_argument("label")
    p_clone.add_argument("new_label")

    # -----------------
    # Bundles
    # -----------------

    p_bundle = sub.add_parser("bundle", help="Bundle operations")
    bsub = p_bundle.add_subparsers(dest="bundle_cmd")

    b_create = bsub.add_parser("create")
    b_create.add_argument("name")
    b_create.add_argument("labels", nargs="+")

    b_run = bsub.add_parser("run")
    b_run.add_argument("name")

    b_delete = bsub.add_parser("delete")
    b_delete.add_argument("name")

    # -----------------
    # Plugins
    # -----------------

    p_plugin = sub.add_parser("plugin", help="Plugin management")
    psub = p_plugin.add_subparsers(dest="plugin_cmd")

    psub.add_parser("list")

    p_inst = psub.add_parser("install")
    p_inst.add_argument("file")

    p_uninst = psub.add_parser("uninstall")
    p_uninst.add_argument("name")

    p_en = psub.add_parser("enable")
    p_en.add_argument("name")

    p_dis = psub.add_parser("disable")
    p_dis.add_argument("name")

    psub.add_parser("enable-all")
    psub.add_parser("disable-all")

    # -----------------
    # VERIFY
    # -----------------

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("label")

    # -----------------
    # BACKUP / RESTORE
    # -----------------

    p_backup = sub.add_parser(
        "backup",
        help="Create FULL SR backup (locked files, plugins, bundles, settings)"
    )
    p_backup.add_argument("--out", help="Output zip file")

    p_restore = sub.add_parser(
        "restore",
        help="Restore FULL SR backup (OVERWRITES EVERYTHING)"
    )
    p_restore.add_argument("file", help="Backup zip file")
    p_restore.add_argument("--force", action="store_true")

    # -----------------
    # EXIT
    # -----------------

    p_exit = sub.add_parser("exit")
    p_exit.add_argument("--force", action="store_true")

    # -----------------
    # Plugins dynamic cmds
    # -----------------

    for name, info in _PLUGIN_COMMANDS.items():
        sub.add_parser(name, help=info.get("help", "Plugin command"))

    args = parser.parse_args()

    try:
        if args.cmd == "lock":
            lock(args.label, args.file, pbkdf2_iter=args.iter)

        elif args.cmd == "run":
            run(args.label)
            
        elif args.cmd == "ghost-run":
            run_ghost(args.label)
            
        elif args.cmd == "get":
            data = get(args.label)
            if data:
                sys.stdout.buffer.write(data)

        elif args.cmd == "relock":
            relock(args.label, pbkdf2_iter=args.iter)

        elif args.cmd == "delete":
            delete(args.label)

        elif args.cmd == "flush":
            flush()

        elif args.cmd == "reset":
            reset(confirm=args.confirm)

        elif args.cmd == "export":
            export_sr(args.label, out_path=args.out)

        elif args.cmd == "import":
            import_sr(args.file, label=args.label)

        elif args.cmd == "info":
            info(
                args.label,
                as_json=args.json,
                show_hash=args.hash,
                show_path=args.path,
                quiet=args.quiet
            )

        elif args.cmd == "labels":
            list_labels()

        elif args.cmd == "rename":
            rename(args.label, args.new_label)

        elif args.cmd == "clone":
            clone(args.label, args.new_label)

        elif args.cmd == "bundle":
            if args.bundle_cmd == "create":
                create_bundle(args.name, args.labels)
            elif args.bundle_cmd == "run":
                run_bundle(args.name)
            elif args.bundle_cmd == "delete":
                delete_bundle(args.name)

        elif args.cmd == "plugin":
            if args.plugin_cmd == "install":
                install_plugin(args.file)
            elif args.plugin_cmd == "uninstall":
                uninstall_plugin(args.name)
            elif args.plugin_cmd == "list":
                for f in sorted(os.listdir(PLUGIN_DIR)):
                    if f.endswith(".py"):
                        print(f[:-3])
            elif args.plugin_cmd == "enable":
                plugin_enable(args.name)
            elif args.plugin_cmd == "disable":
                plugin_disable(args.name)
            elif args.plugin_cmd == "enable-all":
                plugin_enable_all()
            elif args.plugin_cmd == "disable-all":
                plugin_disable_all()

        elif args.cmd == "verify":
            verify(args.label)

        elif args.cmd == "backup":
            backup(out_path=args.out)

        elif args.cmd == "restore":
            if not args.force:
                _warn("Use --force to confirm FULL restore")
            else:
                restore(args.file)

        elif args.cmd == "exit":
            exit_sr(force=args.force)

        elif args.cmd in _PLUGIN_COMMANDS:
            _PLUGIN_COMMANDS[args.cmd]["handler"]()

        else:
            parser.print_help()

    except Exception as e:
        _err(f"Operation failed: {e}")
        if os.environ.get("SR_DEBUG"):
            import traceback
            traceback.print_exc()
        sys.exit(2)
        
def main():
    _ensure_dirs()
    _cli()