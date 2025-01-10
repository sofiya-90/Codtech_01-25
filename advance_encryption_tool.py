import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Encryption Tool")

        self.file_path = ""
        self.history = []

        self.label = tk.Label(master, text="Advanced Encryption Tool", font=("Helvetica", 16, "bold"), fg="blue")
        self.label.pack(pady=10)

        self.creator_label = tk.Label(master, text="Created by: Tulsi Bedarkar", font=("Helvetica", 10), fg="green")
        self.creator_label.pack(pady=5)

        self.encrypt_button = tk.Button(master, text="Encrypt File", command=self.encrypt_file, bg="lightblue", fg="black", font=("Arial", 12, "bold"))
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(master, text="Decrypt File", command=self.decrypt_file, bg="lightgreen", fg="black", font=("Arial", 12, "bold"))
        self.decrypt_button.pack(pady=5)

        self.history_button = tk.Button(master, text="View History", command=self.view_history, bg="lightyellow", fg="black", font=("Arial", 12, "bold"))
        self.history_button.pack(pady=5)

    def get_key(self, password):
        salt = b'\x00' * 16
        return scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)

    def encrypt_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            password = self.get_password("Encrypt")
            if password:
                key = self.get_key(password)
                with open(self.file_path, 'rb') as f:
                    data = f.read()
                
                cipher = AES.new(key, AES.MODE_GCM)
                ciphertext, tag = cipher.encrypt_and_digest(data)

                file_out = self.file_path + ".enc"
                with open(file_out, 'wb') as f:
                    for x in [cipher.nonce, tag, ciphertext]:
                        f.write(x)
                
                self.history.append(f"Encrypted: {self.file_path} to {file_out}")
                messagebox.showinfo("Success", "File encrypted successfully!")
                os.startfile(file_out)

    def decrypt_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if self.file_path:
            password = self.get_password("Decrypt")
            if password:
                key = self.get_key(password)
                with open(self.file_path, 'rb') as f:
                    nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
                
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                try:
                    data = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    messagebox.showerror("Error", "Incorrect password or corrupted file!")
                    return
                
                file_out = os.path.splitext(self.file_path)[0]
                with open(file_out, 'wb') as f:
                    f.write(data)
                
                self.history.append(f"Decrypted: {self.file_path} to {file_out}")
                messagebox.showinfo("Success", "File decrypted successfully!")
                os.startfile(file_out)

    def get_password(self, action):
        password_window = tk.Toplevel(self.master)
        password_window.title(f"{action} File")

        tk.Label(password_window, text="Enter Key:").pack()
        password_entry = tk.Entry(password_window, show="*")
        password_entry.pack()
        show_password_var = tk.IntVar()
        tk.Checkbutton(password_window, text="Show Key", variable=show_password_var, command=lambda: password_entry.config(show="" if show_password_var.get() else "*")).pack()

        def on_submit():
            self.master.password = password_entry.get()
            password_window.destroy()

        tk.Button(password_window, text="Submit", command=on_submit).pack()

        self.master.wait_window(password_window)
        return self.master.password

    def view_history(self):
        history_window = tk.Toplevel(self.master)
        history_window.title("User History")
        
        history_text = tk.Text(history_window)
        history_text.pack()
        
        for item in self.history:
            history_text.insert(tk.END, item + "\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
