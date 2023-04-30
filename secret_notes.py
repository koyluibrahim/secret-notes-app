from tkinter import * #type: ignore
from tkinter import messagebox
import base64
from ctypes import windll
windll.shcore.SetProcessDpiAwareness(1)


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_encrypt():
    title = title_entry.get()
    secret = secret_text.get("1.0", END)
    master_key = master_key_entry.get()

    if len(title) == 0 or len(secret) == 0 or len(master_key) == 0:
        messagebox.showerror(title = "Error", message = "Please fill in completely")
    else:
        encrypted_message = encode(master_key, title)
        with open("top_secret_note.txt", "a") as file:
            file.write(f"{title}\n{encrypted_message}\n")
        title_entry.delete(0, END)
        secret_text.delete(1.0, END)
        master_key_entry.delete(0, END)

def decrypt_notes():
    message_encrypted = secret_text.get("1.0", END)
    master_secret = master_key_entry.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please fill in completely")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")

window = Tk()
window.title("Secret Notes")
window.minsize(400, 500)
window.config(padx = 50, pady = 20)

title_label = Label(text = "Enter Your Title", font = ("Arial", 10, "normal"), padx = 10, pady = 10)
title_label.pack()

title_entry = Entry(width = 40)
title_entry.pack()

secret_label = Label(text = "Enter Your Secret", font = ("Arial", 10, "normal"), padx = 10, pady = 10)
secret_label.pack()

secret_text = Text(width = 32, height = 10)
secret_text.pack()

master_key_label = Label(text = "Enter Your Master Key", font = ("Arial", 10, "normal"), padx = 10, pady = 10)
master_key_label.pack()

master_key_entry = Entry(width = 40)
master_key_entry.pack()

save_button = Button(text="Save and Encrypt", command = save_encrypt)
save_button.pack(side = "left")

decrypt_button = Button(text="Decrypt", command = decrypt_notes)
decrypt_button.pack(side = "right")

window.mainloop()