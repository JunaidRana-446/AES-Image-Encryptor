# ================= CORE AES ENCRYPTION / DECRYPTION LOGIC WITH ANALYTICS =================

import os
import json
import base64
import time
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import numpy as np
import matplotlib.pyplot as plt

HISTORY_FILE = "encryption_history.json"

# ---------------- Base64 Helpers -----------------

def b64(b):
    return base64.b64encode(b).decode() if b else None

def ub64(s):
    return base64.b64decode(s) if s else None

# ---------------- Key Derivation -----------------

def derive_key(password, key_size, iterations=200000):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=key_size // 8, count=iterations)
    return key, salt, iterations

# ---------------- History Logging -----------------

def log_history(entry):
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            history = json.load(f)
    else:
        history = []
    history.append(entry)
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

# ---------------- Encryption -----------------

def encrypt_image(image_path, mode, key_size, use_password=False, password=None):
    start_time = time.time()
    img = Image.open(image_path).convert('RGB')
    width, height = img.size
    raw = np.array(img).tobytes()

    if use_password:
        key, salt, iters = derive_key(password, key_size)
    else:
        key = get_random_bytes(key_size // 8)
        salt = None
        iters = None

    iv = None
    tag = None

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
        raise ValueError('Unsupported AES mode')

    base = os.path.splitext(os.path.basename(image_path))[0]
    bin_path = f"{base}_{mode}.bin"
    with open(bin_path, 'wb') as f:
        f.write(ct)

    preview_bytes = ct[:len(raw)]
    preview_arr = np.frombuffer(preview_bytes, dtype=np.uint8).reshape((height, width, 3))
    preview_path = f"encrypted_{mode}.png"
    Image.fromarray(preview_arr).save(preview_path)

    meta = {
        'mode': mode,
        'key_size': key_size,
        'salt': b64(salt),
        'iterations': iters,
        'iv_or_nonce': b64(iv),
        'tag': b64(tag),
        'width': width,
        'height': height,
        'used_password': use_password,
        'key_hex': None if use_password else key.hex(),
        'cipher_bin': bin_path,
        'preview_image': preview_path,
        'original_filename': os.path.basename(image_path),
        'timestamp': datetime.now().isoformat(),
        'time_taken_sec': None,
        'security_rating': None
    }

    ratings = {'ECB': 3, 'CBC': 4, 'OFB': 4, 'CTR': 5, 'GCM': 5}
    meta['security_rating'] = ratings.get(mode, 3)

    end_time = time.time()
    meta['time_taken_sec'] = round(end_time - start_time, 3)

    meta_path = f"{base}_{mode}.metadata.json"
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)

    log_history(meta)

    return preview_path, bin_path, meta_path

# ---------------- Metadata Loader -----------------

def load_metadata_auto(path):
    if path.lower().endswith('.json'):
        with open(path, 'r') as f:
            return json.load(f)

    if path.lower().endswith('.bin'):
        base = path[:-4]
        jpath = base + '.metadata.json'
        if not os.path.exists(jpath):
            raise FileNotFoundError("Metadata JSON missing: " + jpath)
        with open(jpath, 'r') as f:
            return json.load(f)

    raise ValueError('Provide .json or .bin file')

# ---------------- Decryption -----------------

def decrypt_image(meta_or_bin_path, password=None, key_hex=None):
    meta = load_metadata_auto(meta_or_bin_path)

    mode = meta['mode']
    width = meta['width']
    height = meta['height']
    salt = ub64(meta.get('salt'))
    iters = meta.get('iterations')
    iv = ub64(meta.get('iv_or_nonce'))
    tag = ub64(meta.get('tag'))
    bin_path = meta['cipher_bin']

    if meta['used_password']:
        if not password:
            raise ValueError('Password is required for decryption')
        key = PBKDF2(password, salt, dkLen=meta['key_size'] // 8, count=iters)
    else:
        if not key_hex:
            raise ValueError('Key hex required because no password was used')
        key = bytes.fromhex(key_hex)

    with open(bin_path, 'rb') as f:
        ct = f.read()

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
        pt = cipher.decrypt_and_verify(ct, tag)

    else:
        raise ValueError('Unknown AES mode')

    arr = np.frombuffer(pt, dtype=np.uint8).reshape((height, width, 3))
    out = f"decrypted_{meta['original_filename']}"
    Image.fromarray(arr).save(out)
    return out

# ====================== CUSTOM TKINTER GUI WITH ANALYTICS ======================

if __name__ == '__main__':
    import customtkinter as ctk
    from tkinter import filedialog, messagebox, simpledialog
    from PIL import Image, ImageTk

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    class AESCustomGUI(ctk.CTk):
        def __init__(self):
            super().__init__()
            self.title("AES Image Encryptor & Analyzer")
            self.geometry("1100x800")

            self.img_path = ctk.StringVar()
            self.meta_path = ctk.StringVar()
            self.password = ctk.StringVar()
            self.keyhex = ctk.StringVar()

            self.build_ui()

        def build_ui(self):
            # ================= Title =================
            ctk.CTkLabel(self, text="AES Image Encryption & Security Analyzer", font=("Arial", 28, "bold"), text_color="#00ffcc").pack(pady=15)

            main_frame = ctk.CTkFrame(self)
            main_frame.pack(fill='both', expand=True, padx=20, pady=10)

            # ================= Top Frames =================
            top_frame = ctk.CTkFrame(main_frame)
            top_frame.pack(fill='x', pady=10)

            # ----- Top Left: Image Selection -----
            img_frame = ctk.CTkFrame(top_frame)
            img_frame.pack(side='left', padx=10, fill='y')
            ctk.CTkLabel(img_frame, text="Select File (Image or BIN/JSON):", font=('Arial', 14, 'bold')).pack(pady=5)
            ctk.CTkEntry(img_frame, textvariable=self.img_path, width=400).pack(pady=5)
            ctk.CTkButton(img_frame, text="Browse", command=self.load_file).pack(pady=5)
            self.preview_label = ctk.CTkLabel(img_frame, text="Preview", width=400, height=200, fg_color="#3333ff")
            self.preview_label.pack(pady=5)

            # Buttons moved just below preview
            ctk.CTkButton(img_frame, text="Encrypt", command=self.do_encrypt, width=180).pack(pady=5)
            ctk.CTkButton(img_frame, text="Decrypt", command=self.do_decrypt, width=180).pack(pady=5)

            # ----- Top Right: Options & Summary -----
            options_frame = ctk.CTkFrame(top_frame)
            options_frame.pack(side='left', padx=50, fill='y')
            ctk.CTkLabel(options_frame, text="AES Mode:", font=('Arial', 14, 'bold')).pack(pady=5)
            self.mode_box = ctk.CTkComboBox(options_frame, values=["ECB","CBC","OFB","CTR","GCM"])
            self.mode_box.pack(pady=5)

            ctk.CTkLabel(options_frame, text="Key Size:", font=('Arial', 14, 'bold')).pack(pady=5)
            self.key_box = ctk.CTkComboBox(options_frame, values=["128","192","256"])
            self.key_box.pack(pady=5)

            ctk.CTkLabel(options_frame, text="Password:", font=('Arial', 14, 'bold')).pack(pady=5)
            ctk.CTkEntry(options_frame, textvariable=self.password, show="*").pack(pady=5)

            # Summary textbox moved here
            ctk.CTkLabel(options_frame, text="Encryption Summary", font=('Arial', 16, 'bold'), text_color="#00ffcc").pack(pady=10)
            self.summary_text = ctk.CTkTextbox(options_frame, width=300, height=200, corner_radius=5)
            self.summary_text.pack(pady=5, fill='both', expand=True)
            self.summary_text.configure(state='normal', wrap='none')
            self.summary_text_scroll = ctk.CTkScrollbar(options_frame, orientation='vertical', command=self.summary_text.yview)
            self.summary_text.configure(yscrollcommand=self.summary_text_scroll.set)
            self.summary_text_scroll.pack(side='right', fill='y')

            # Plot graph button (popup)
            ctk.CTkButton(options_frame, text="Plot Graph", command=self.plot_history_popup).pack(pady=10)

        def update_summary(self, meta):
            self.summary_text.configure(state='normal')
            self.summary_text.delete('1.0', 'end')
            summary = f"Mode Used: {meta['mode']}\nKey Size: {meta['key_size']}\nPassword Used: {meta['used_password']}\nTime Taken: {meta['time_taken_sec']} sec\nSecurity Rating: {meta['security_rating']}\nOriginal Image: {meta['original_filename']}"
            self.summary_text.insert('1.0', summary)
            self.summary_text.configure(state='disabled')

        def load_file(self):
            path = filedialog.askopenfilename(filetypes=[("All Files", "*.png;*.jpg;*.jpeg;*.bmp;*.bin;*.json")])
            if path:
                self.img_path.set(path)

        def do_encrypt(self):
            try:
                preview, binf, meta_path = encrypt_image(
                    self.img_path.get(),
                    self.mode_box.get(),
                    int(self.key_box.get()),
                    use_password=bool(self.password.get()),
                    password=self.password.get() if self.password.get() else None
                )
                img = Image.open(preview).resize((300,300))
                img = ImageTk.PhotoImage(img)
                self.preview_label.configure(image=img, text="")
                self.preview_label.image = img

                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                self.update_summary(meta)

                messagebox.showinfo("Success", f"Encrypted!\nPreview: {preview}\nBIN: {binf}\nMetadata: {meta_path}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        def do_decrypt(self):
            try:
                out = decrypt_image(
                    self.img_path.get(),
                    password=self.password.get() if self.password.get() else None,
                    key_hex=self.keyhex.get() if self.keyhex.get() else None
                )
                messagebox.showinfo("Success", f"Decrypted Image: {out}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        def plot_history_popup(self):
            if not os.path.exists(HISTORY_FILE):
                messagebox.showinfo("History", "No encryption history found.")
                return

            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
            total = len(history)
            if total == 0:
                messagebox.showinfo("History", "No encryption history found.")
                return

            n = simpledialog.askinteger("Input", f"Enter number of last encryptions to plot (max {total}):", minvalue=1, maxvalue=total)
            if not n:
                return

            times = [entry['time_taken_sec'] for entry in history[-n:]]
            modes = [entry['mode'] for entry in history[-n:]]
            plt.figure(figsize=(6,4))
            plt.plot(modes, times, color='#00ccff')
            plt.scatter(modes, times, color='#00ccff')
            plt.ylabel('Time Taken (sec)')
            plt.title(f'Last {n} Encryption Times')
            plt.show()

    app = AESCustomGUI()
    app.mainloop()
