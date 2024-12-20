import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from os import urandom


###########################
# Génération de clé
def GenKey(length):
    return bytearray(urandom(length))


###########################
# Fonctions de chiffrement/déchiffrement
def encrypt1(plain_block, key):
    return bytearray(plain_block[i] ^ key[i] for i in range(len(plain_block)))


def encrypt2(plain_block, key):
    return bytearray(plain_block[i] ^ key[i] for i in range(len(plain_block)))


def encrypt_message(blockList, key, iv):
    list_of_ciphers = []
    for i in range(len(blockList)):
        cipher1 = encrypt1(blockList[i], iv)
        cipher2 = encrypt2(cipher1, key)
        list_of_ciphers.append(cipher2)
        iv = cipher2
    return list_of_ciphers


def decrypt1(cipher, key):
    return bytearray(cipher[i] ^ key[i] for i in range(len(cipher)))


def decrypt_cipher(list_cipher, key, iv):
    list_of_decrypted_blocks = []
    for i in range(len(list_cipher)):
        temp = decrypt1(list_cipher[i], key)
        plain = decrypt1(temp, iv)
        list_of_decrypted_blocks.append(plain)
        iv = list_cipher[i]
    return b''.join(list_of_decrypted_blocks)


###########################
# Gestion des fichiers
def BreakFile(file_bytes, len_of_block):
    list_of_blocks = []
    padding_needed = len_of_block - (len(file_bytes) % len_of_block)
    file_bytes += bytes([padding_needed]) * padding_needed  # Padding PKCS#7

    for i in range(0, len(file_bytes), len_of_block):
        block = file_bytes[i:i + len_of_block]
        list_of_blocks.append(bytearray(block))
    return list_of_blocks


###########################
# Chiffrement de texte
def encrypt_text(message):
    len_of_block = 8
    blockList = BreakFile(message.encode('utf-8'), len_of_block)
    key = GenKey(len_of_block)
    iv = GenKey(len_of_block)
    cipher_list = encrypt_message(blockList, key, iv)
    encrypted_text = b''.join(cipher_list)
    with open('text.enc', 'wb') as f_out:
        original_size = len(encrypted_text)
        f_out.write(original_size.to_bytes(4, 'big'))
        for cipher in cipher_list:
            f_out.write(cipher)
    return encrypted_text, key.hex(), iv.hex()


def decrypt_text(encrypted_text, key, iv):
    len_of_block = 8
    cipher_bytes = bytes.fromhex(encrypted_text)
    blockList = BreakFile(cipher_bytes, len_of_block)
    key = bytearray.fromhex(key)
    iv = bytearray.fromhex(iv)
    decrypted_bytes = decrypt_cipher(blockList, key, iv)
    padding_length = decrypted_bytes[-1]
    return decrypted_bytes[:-padding_length].decode('utf-8')


###########################
# Chiffrement de fichiers
def encrypt_file(file_path):
    len_of_block = 8
    with open(file_path, 'rb') as f_in:
        file_bytes = f_in.read()

    blockList = BreakFile(file_bytes, len_of_block)
    key = GenKey(len_of_block)
    iv = GenKey(len_of_block)
    cipher_list = encrypt_message(blockList, key, iv)

    with open(file_path + '.enc', 'wb') as f_out:
        original_size = len(file_bytes)
        f_out.write(original_size.to_bytes(4, 'big'))
        for cipher in cipher_list:
            f_out.write(cipher)

    return key.hex(), iv.hex()


def decrypt_file(file_path, key, iv):
    len_of_block = 8
    with open(file_path, 'rb') as f_in:
        original_size = int.from_bytes(f_in.read(4), 'big')
        cipher_bytes = f_in.read()

    blockList = BreakFile(cipher_bytes, len_of_block)
    key = bytearray.fromhex(key)
    iv = bytearray.fromhex(iv)
    decrypted_bytes = decrypt_cipher(blockList, key, iv)
    decrypted_bytes = decrypted_bytes[:original_size]

    output_file = file_path.replace('.enc', '_decrypted')
    with open(output_file, 'wb') as f_out:
        f_out.write(decrypted_bytes)


###########################
# Interface Utilisateur
def encrypt():
    def select_option():
        choice = messagebox.askyesno(
            "Type de chiffrement",
            "Voulez-vous chiffrer un fichier ? (Oui = fichier, Non = message texte)"
        )
        if choice:
            file_path = filedialog.askopenfilename(title="Select File to Encrypt")
            if file_path:
                key, iv = encrypt_file(file_path)
                print(f"Key : {key}")
                print(f"IV : {iv}")
                print(f" The encrypted text is stored in '{file_path}.enc'")
                messagebox.showinfo("Success", f"Key: {key}\nIV: {iv}")
                messagebox.showinfo("Success", f" The encrypted text is stored in '{file_path}.enc'")
        else:
            message = simpledialog.askstring("Input", "Enter your message to encrypt:")
            if message:
                encrypted_text, key, iv = encrypt_text(message)

                print(f"Key : {key}")
                print(f"IV : {iv}")
                print(f" The encrypted text is stored in 'text.enc'")
                messagebox.showinfo("Success", f"Key: {key}\nIV: {iv}")
                messagebox.showinfo("Success", " The encrypted text is stored in 'text.enc'")


    select_option()


def decrypt():

    file_path = filedialog.askopenfilename(title="Select File to Decrypt")
    if file_path:
        key = simpledialog.askstring("Key Input", "Enter Key (hex):")
        iv = simpledialog.askstring("IV Input", "Enter IV (hex):")
        if key and iv:
            decrypt_file(file_path, key, iv)
            messagebox.showinfo("Success", f" The encrypted text is stored in '{file_path.replace('.enc', '_decrypted')}'")

###########################
def main():
    main_window = tk.Tk()
    main_window.title("CryptBC")
    main_window.geometry("300x200")

    welcome_label = tk.Label(main_window, text="Welcome to CryptBC!")
    welcome_label.pack()

    encrypt_button = tk.Button(main_window, text="Encrypt", command=encrypt)
    encrypt_button.pack(side=tk.LEFT, padx=10)

    decrypt_button = tk.Button(main_window, text="Decrypt", command=decrypt)
    decrypt_button.pack(side=tk.LEFT, padx=10)

    main_window.mainloop()


###########################
main()

# CBC_XOR v2.3
# Ajouts :
#   - Fonctionnalité de chiffrement pour les messages textuels avec sauvegarde dans text.enc.
#   - Simplification des interfaces utilisateur pour offrir des options entre chiffrement de texte ou de fichiers.
#   - Gestion améliorée des exceptions dans les processus d’entrée et de sortie.
#   - Retrait de certains commentaires obsolètes pour rendre le code plus lisible.
# Modifications :
#   - Début de l’ajout de logs pour tracer les actions effectuées (dans une forme basique).