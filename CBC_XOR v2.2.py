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


def decrypt2(cipher, key):
    return bytearray(cipher[i] ^ key[i] for i in range(len(cipher)))


def decrypt_cipher(list_cipher, key, iv):
    list_of_decrypted_blocks = []
    for i in range(len(list_cipher)):
        temp = decrypt1(list_cipher[i], key)
        plain = decrypt2(temp, iv)
        list_of_decrypted_blocks.append(plain)
        iv = list_cipher[i]
    return list_of_decrypted_blocks


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


def encrypt_file(file_path):
    key_iv = {"key": "", "iv": ""}
    len_of_block = 8

    print(f"[INFO] Lecture du fichier : {file_path}")

    with open(file_path, 'rb') as f_in:
        file_bytes = f_in.read()

    print(f"[INFO] Taille du fichier lue : {len(file_bytes)} octets")

    blockList = BreakFile(file_bytes, len_of_block)
    print(f"[INFO] Fichier divisé en {len(blockList)} blocs de {len_of_block} octets")

    key = GenKey(len_of_block)
    iv = GenKey(len_of_block)
    print(f"[INFO] Clé générée : {key.hex()}")
    print(f"[INFO] IV généré : {iv.hex()}")

    cipher_list = encrypt_message(blockList, key, iv)
    print(f"[INFO] Chiffrement terminé, sauvegarde en cours...")

    with open(file_path + '.enc', 'wb') as f_out:
        original_size = len(file_bytes)
        f_out.write(original_size.to_bytes(4, 'big'))
        for cipher in cipher_list:
            f_out.write(cipher)

    print(f"[SUCCESS] Fichier chiffré sauvegardé sous : {file_path}.enc")
    key_iv["key"] = key.hex()
    key_iv["iv"] = iv.hex()

    return key_iv


def decrypt_file(file_path, key, iv):
    len_of_block = 8

    print(f"[INFO] Déchiffrement du fichier : {file_path}")

    with open(file_path, 'rb') as f_in:
        original_size = int.from_bytes(f_in.read(4), 'big')
        cipher_bytes = f_in.read()

    blockList = BreakFile(cipher_bytes, len_of_block)
    print(f"[INFO] Fichier chiffré divisé en {len(blockList)} blocs")

    key = bytearray.fromhex(key)
    iv = bytearray.fromhex(iv)
    decrypted_list = decrypt_cipher(blockList, key, iv)
    decrypted_bytes = b''.join(decrypted_list)

    decrypted_bytes = decrypted_bytes[:original_size]
    print("[INFO] Déchiffrement terminé, suppression du padding en cours...")

    output_file = file_path.replace('.enc', '_decrypted')
    with open(output_file, 'wb') as f_out:
        f_out.write(decrypted_bytes)

    print(f"[SUCCESS] Fichier déchiffré sauvegardé sous : {output_file}")


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
                key_iv = encrypt_file(file_path)
                messagebox.showinfo("Success", f"Key: {key_iv['key']}\nIV: {key_iv['iv']}")
        else:
            myMessage = simpledialog.askstring("Input", "Enter your message to encrypt:")
            if myMessage:
                len_of_block = 8
                blockList = BreakFile(myMessage.encode(), len_of_block)
                key = GenKey(len_of_block)
                iv = GenKey(len_of_block)
                cipher_list = encrypt_message(blockList, key, iv)
                encrypted_text = b''.join(cipher_list).hex()
                messagebox.showinfo("Encrypted Message", f"Encrypted Text: {encrypted_text}\nKey: {key.hex()}\nIV: {iv.hex()}")
            print(f"Key : {key.hex()}")
            print(f"IV : {iv.hex()}")
    select_option()


def decrypt():
    file_path = filedialog.askopenfilename(title="Select File to Decrypt")
    if file_path:
        key = simpledialog.askstring("Key Input", "Enter Key (hex):")
        iv = simpledialog.askstring("IV Input", "Enter IV (hex):")
        if key and iv:
            decrypt_file(file_path, key, iv)


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

# CBC_XOR v2.2

# Ajouts :
#    - Introduction des fonctions de chiffrement et déchiffrement pour les fichiers.
#    - Découpage explicite en blocs pour le traitement des données binaires des fichiers.
#    - Sauvegarde des fichiers déchiffrés avec un suffixe _decrypted.
#    - Vérification et validation des entrées utilisateur via messagebox et filedialog.
# Modifications :
#    - Uniformisation du code entre les fonctions pour le traitement des messages et des fichiers.