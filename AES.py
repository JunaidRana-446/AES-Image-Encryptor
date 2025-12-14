"""
AES Image Encryptor — Fixed (Option A)

Behavior summary:
- Encrypts images and saves the **full ciphertext** to a `.bin` file (this is the real ciphertext).
- Also writes a small PNG preview constructed from the first N bytes so you can visually inspect an "encrypted-looking" image.
- Decryption reads the full ciphertext from the `.bin` file and reconstructs the original image.
- Supports AES modes: ECB, CBC, OFB, CTR, GCM
- Supports AES key sizes: 128, 192, 256
- Optional PBKDF2 (password-derived key)

This file is intentionally simple so an average Python user can follow it.

Dependencies: pycryptodome, pillow, numpy

Run interactively: python aes_fixed.py
"""

import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import numpy as np

# ---------- Helpers ----------

def b64(b):
    return base64.b64encode(b).decode() if b else None


def ub64(s):
    return base64.b64decode(s) if s else None


def derive_key(password, key_size, iterations=200000):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=key_size // 8, count=iterations)
    return key, salt, iterations


# ---------- Encryption ----------

def encrypt_image(image_path, mode, key_size, use_password=False, password=None):
    img = Image.open(image_path).convert('RGB')
    width, height = img.size
    raw = np.array(img).tobytes()

    # Key
    if use_password:
        key, salt, iters = derive_key(password, key_size)
    else:
        key = get_random_bytes(key_size // 8)
        salt = None
        iters = None

    iv = None
    tag = None

    # Choose mode
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(raw, AES.block_size))

    elif mode == 'CBC':
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(pad(raw, AES.block_size))

    elif mode == 'OFB':
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
        ct = cipher.encrypt(raw)

    elif mode == 'CTR':
        nonce = get_random_bytes(8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ct = cipher.encrypt(raw)
        iv = nonce

    elif mode == 'GCM':
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(raw)
        iv = nonce

    else:
        raise ValueError('Unsupported mode')

    # Save full ciphertext to .bin (this is the canonical ciphertext)
    base = os.path.splitext(os.path.basename(image_path))[0]
    bin_path = f"{base}_{mode}.bin"
    with open(bin_path, 'wb') as f:
        f.write(ct)

    # Create a preview PNG from the first N bytes of ciphertext (visual only)
    preview_bytes = ct[:len(raw)]  # same length as original image bytes
    preview_arr = np.frombuffer(preview_bytes, dtype=np.uint8).reshape((height, width, 3))
    preview_path = f"encrypted_{mode}.png"
    Image.fromarray(preview_arr).save(preview_path)

    # Metadata (store iv/nonce, tag, salt if used, and dimensions)
    metadata = {
        'mode': mode,
        'key_size': key_size,
        'salt': b64(salt),
        'iterations': iters,
        'iv_or_nonce': b64(iv),
        'tag': b64(tag),
        'width': width,
        'height': height,
        'used_password': bool(use_password),
        'key_hex': None if use_password else key.hex(),
        'cipher_bin': bin_path,
        'preview_image': preview_path,
        'original_filename': os.path.basename(image_path)
    }

    meta_path = f"{base}_{mode}.metadata.json"
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    return preview_path, bin_path, meta_path


# ---------- Decryption ----------

# New helper: try to load metadata from JSON OR from a .bin filename

def load_metadata_auto(path):
    # If JSON provided
    if path.lower().endswith('.json'):
        with open(path, 'r') as f:
            return json.load(f)

    # If BIN provided → auto-detect matching JSON
    if path.lower().endswith('.bin'):
        base = path[:-4]  # remove .bin
        # example: image_CBC.bin → image_CBC.metadata.json
        json_path = base + '.metadata.json'
        if not os.path.exists(json_path):
            raise FileNotFoundError('BIN provided but matching metadata JSON not found: ' + json_path)
        with open(json_path, 'r') as f:
            return json.load(f)

    raise ValueError('Unsupported file type. Provide .json or .bin')


def decrypt_image(meta_or_bin_path, password=None, key_hex=None):
    # Load metadata (from JSON or auto from BIN)
    meta = load_metadata_auto(meta_or_bin_path)

    mode = meta['mode']
    width = meta['width']
    height = meta['height']
    salt = ub64(meta.get('salt'))
    iters = meta.get('iterations')
    iv = ub64(meta.get('iv_or_nonce'))
    tag = ub64(meta.get('tag'))
    used_password = meta.get('used_password')
    bin_path = meta.get('cipher_bin')

    if used_password:
        if not password:
            raise ValueError('Password required for PBKDF2 decryption')
        key = PBKDF2(password, salt, dkLen=meta['key_size'] // 8, count=iters) # type: ignore
    else:
        if not key_hex:
            raise ValueError('Key hex required when password was not used')
        key = bytes.fromhex(key_hex)

    # Read full ciphertext
    with open(bin_path, 'rb') as f:
        ct = f.read()

    # Decrypt
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ct), AES.block_size)

    elif mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)

    elif mode == 'OFB':
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
        pt = cipher.decrypt(ct)

    elif mode == 'CTR':
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        pt = cipher.decrypt(ct)

    elif mode == 'GCM':
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        try:
            pt = cipher.decrypt_and_verify(ct, tag) # type: ignore
        except ValueError:
            raise ValueError('GCM authentication failed — wrong password or corrupted data')

    else:
        raise ValueError('Unsupported mode in metadata')

    # Rebuild image
    arr = np.frombuffer(pt, dtype=np.uint8).reshape((height, width, 3))
    out_name = f"decrypted_{meta.get('original_filename', 'output.png')}"
    Image.fromarray(arr).save(out_name)

    return out_name


# ---------- Simple CLI ----------

if __name__ == '__main__':
    print('1. Encrypt Image')
    print('2. Decrypt Image')
    choice = input('Choose option: ').strip()

    if choice == '1':
        path = input('Enter image path: ').strip()
        print('Modes: ECB CBC OFB CTR GCM')
        mode = input('Mode (name): ').strip().upper()
        key_size = int(input('Key size (128/192/256): ').strip())
        use_pw = input('Use password? (y/n): ').strip().lower() == 'y'
        pw = None
        if use_pw:
            pw = input('Enter password: ')

        preview, bin_file, meta = encrypt_image(path, mode, key_size, use_password=use_pw, password=pw)
        print('Encryption complete!')
        print('Preview image:', preview)
        print('Ciphertext bin:', bin_file)
        print('Metadata file:', meta)

    elif choice == '2':
        meta = input('Enter metadata path: ').strip()
        with open(meta, 'r') as f:
            m = json.load(f)
        if m.get('used_password'):
            pw = input('Enter password: ')
            out = decrypt_image(meta, password=pw)
        else:
            key_hex = input('Enter key hex (from .key file): ').strip()
            out = decrypt_image(meta, key_hex=key_hex)
        print('Decryption complete!')
        print('Decrypted image saved to:', out)

    else:
        print('Invalid option')
