import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np

# Helper: PKCS#7 padding

def pad(data):
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len]) * pad_len


# ENCRYPT IMAGE

def encrypt_image(image_path, mode_name):

    img = Image.open(image_path).convert("RGB")
    width, height = img.size
    img_array = np.array(img)
    img_bytes = img_array.tobytes()

    key = get_random_bytes(16)

    # Select AES mode
    if mode_name == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        iv_nonce = None

    elif mode_name == "CBC":
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        iv_nonce = iv

    elif mode_name == "OFB":
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
        iv_nonce = iv

    elif mode_name == "CTR":
        nonce = get_random_bytes(8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        iv_nonce = nonce

    else:
        print("Invalid mode!")
        return

    padded = pad(img_bytes)
    encrypted = cipher.encrypt(padded)

    encrypted = encrypted[:len(img_bytes)]

    encrypted_array = np.frombuffer(encrypted, dtype=np.uint8)
    encrypted_array = encrypted_array.reshape(img_array.shape)

    encrypted_img = Image.fromarray(encrypted_array)
    output_image = f"encrypted_{mode_name}.png"
    encrypted_img.save(output_image)

    # Save metadata including size
    meta_file = f"metadata_{mode_name}.txt"
    with open(meta_file, "w") as f:
        f.write("AES Image Encryption Metadata\n")
        f.write(f"MODE: {mode_name}\n")
        f.write(f"KEY: {key.hex()}\n")
        f.write(f"WIDTH: {width}\n")
        f.write(f"HEIGHT: {height}\n")
        if iv_nonce:
            f.write(f"IV_OR_NONCE: {iv_nonce.hex()}\n")
        else:
            f.write("IV_OR_NONCE: NONE\n")

    print(f"\n[✔] Encryption Completed!")
    print(f"[•] Encrypted image saved as: {output_image}")
    print(f"[•] Metadata saved as: {meta_file}\n")



# LOAD METADATA FOR DECRYPTION

def load_metadata(meta_path):
    if not os.path.exists(meta_path):
        print("Metadata file not found!")
        return None, None, None, None, None

    mode = None
    key = None
    width = None
    height = None
    iv_or_nonce = None

    with open(meta_path, "r") as f:
        lines = f.readlines()

    for line in lines:
        if line.startswith("MODE:"):
            mode = line.split(":", 1)[1].strip()

        elif line.startswith("KEY:"):
            key = bytes.fromhex(line.split(":", 1)[1].strip())

        elif line.startswith("WIDTH:"):
            width = int(line.split(":", 1)[1].strip())

        elif line.startswith("HEIGHT:"):
            height = int(line.split(":", 1)[1].strip())

        elif line.startswith("IV_OR_NONCE:"):
            val = line.split(":", 1)[1].strip()
            iv_or_nonce = None if val == "NONE" else bytes.fromhex(val)

    return mode, key, iv_or_nonce, width, height


# DECRYPT IMAGE

def decrypt_image(encrypted_path, metadata_path):

    mode, key, iv_nonce, width, height = load_metadata(metadata_path)

    if None in (mode, key, width, height):
        print("Metadata incomplete. Cannot decrypt.")
        return

    # Load encrypted image
    enc_img = Image.open(encrypted_path).convert("RGB")
    enc_array = np.array(enc_img)
    enc_bytes = enc_array.tobytes()

    # Fix padded length
    padded_len = (len(enc_bytes) + AES.block_size) // AES.block_size * AES.block_size
    padded_data = enc_bytes + b"\x00" * (padded_len - len(enc_bytes))

    # Re-create AES object
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB) # type: ignore

    elif mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv=iv_nonce) # type: ignore

    elif mode == "OFB":
        cipher = AES.new(key, AES.MODE_OFB, iv=iv_nonce) # type: ignore

    elif mode == "CTR":
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv_nonce) # type: ignore

    else:
        print("Unknown AES mode in metadata.")
        return

    decrypted = cipher.decrypt(padded_data)
    decrypted = decrypted[:len(enc_bytes)]

    dec_array = np.frombuffer(decrypted, dtype=np.uint8)
    dec_array = dec_array.reshape((height, width, 3)) # type: ignore

    output_img = "decrypted_output.png"
    Image.fromarray(dec_array).save(output_img)

    print("\n[✔] Decryption Completed!")
    print(f"[•] Decrypted image saved as: {output_img}\n")


# MAIN MENU

def main():
    print("\n===== AES IMAGE ENCRYPTION & DECRYPTION TOOL =====\n")

    print("1. Encrypt Image")
    print("2. Decrypt Image")

    choice = input("\nSelect an option: ").strip()

    if choice == "1":
        path = input("Enter image path: ").strip()

        print("\nSelect AES Mode:")
        print("1. ECB")
        print("2. CBC")
        print("3. OFB")
        print("4. CTR")

        mode_choice = input("Enter mode: ").strip()
        modes = {"1": "ECB", "2": "CBC", "3": "OFB", "4": "CTR"}

        if mode_choice not in modes:
            print("Invalid mode.")
            return

        encrypt_image(path, modes[mode_choice])

    elif choice == "2":
        encrypted_path = input("Enter encrypted image path: ").strip()
        meta_path = input("Enter metadata file path: ").strip()

        decrypt_image(encrypted_path, meta_path)

    else:
        print("Invalid option.")


if __name__ == "__main__":
    main()
