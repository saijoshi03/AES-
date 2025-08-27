from tkinter import *
from tkinter import messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# AES always works on blocks of 16 bytes
BLOCK_SIZE = 16  

# --- Function to make sure key is valid length ---
def normalize_key(key_str: str) -> bytes:
    key_b = key_str.encode('utf-8')
    if len(key_b) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 characters for AES-128/192/256.")
    return key_b

# --- Encryption Function ---
def encrypt(plaintext: str, key_str: str) -> str:
    key = normalize_key(key_str)
    data = plaintext.encode('utf-8')
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, BLOCK_SIZE))
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

# --- Decryption Function ---
def decrypt(b64_ciphertext: str, key_str: str) -> str:
    key = normalize_key(key_str)
    raw = base64.b64decode(b64_ciphertext)
    iv = raw[:BLOCK_SIZE]
    ct = raw[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ct)
    return unpad(pt_padded, BLOCK_SIZE).decode('utf-8')

# --- GUI Functions ---
def do_encrypt():
    try:
        plaintext = text_input.get("1.0", END).strip()
        key = key_input.get().strip()
        if not plaintext or not key:
            messagebox.showerror("Error", "Please enter text and key.")
            return
        ciphertext = encrypt(plaintext, key)
        output_box.delete("1.0", END)
        output_box.insert(END, ciphertext)
    except ValueError as e:
        messagebox.showerror("Error", str(e))

def do_decrypt():
    try:
        ciphertext = text_input.get("1.0", END).strip()
        key = key_input.get().strip()
        if not ciphertext or not key:
            messagebox.showerror("Error", "Please enter ciphertext and key.")
            return
        plaintext = decrypt(ciphertext, key)
        output_box.delete("1.0", END)
        output_box.insert(END, plaintext)
    except ValueError as e:
        messagebox.showerror("Error", str(e))
    except Exception:
        messagebox.showerror("Error", "Wrong key or corrupted ciphertext.")

# --- Tkinter GUI ---
root = Tk()
root.title("AES Encryption/Decryption Tool")
root.geometry("600x500")

Label(root, text=" AES Encryption/Decryption Tool", font=("Arial", 16, "bold")).pack(pady=10)

# Key entry
Label(root, text="Enter Secret Key (16/24/32 chars):", font=("Arial", 12)).pack()
key_input = Entry(root, width=40, show="*", font=("Arial", 12))
key_input.pack(pady=5)

# Input text area
Label(root, text="Enter Plaintext or Ciphertext (Base64):", font=("Arial", 12)).pack()
text_input = scrolledtext.ScrolledText(root, wrap=WORD, width=70, height=8, font=("Arial", 11))
text_input.pack(pady=5)

# Buttons
frame = Frame(root)
frame.pack(pady=10)
Button(frame, text="Encrypt", command=do_encrypt, width=15, bg="lightgreen", font=("Arial", 12, "bold")).grid(row=0, column=0, padx=10)
Button(frame, text="Decrypt", command=do_decrypt, width=15, bg="lightblue", font=("Arial", 12, "bold")).grid(row=0, column=1, padx=10)

# Output text area
Label(root, text="Output:", font=("Arial", 12)).pack()
output_box = scrolledtext.ScrolledText(root, wrap=WORD, width=70, height=8, font=("Arial", 11))
output_box.pack(pady=5)

root.mainloop()
