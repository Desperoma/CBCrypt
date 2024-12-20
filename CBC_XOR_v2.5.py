import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from os import urandom


###########################
# Génération de clé
def GenKey(length):
    print(f"[INFO] Generating key of length: {length}")
    return bytearray(urandom(length))


###########################
# Fonctions de chiffrement/déchiffrement
def encrypt1(plain_block, key):
    return bytearray(plain_block[i] ^ key[i] for i in range(len(plain_block)))



def encrypt_message(blockList, key, iv):
    print(f"[INFO] Starting message encryption")
    list_of_ciphers = []
    for i in range(len(blockList)):
        if (i+1) % 10 == 0:
            print(f"[LOG] Encrypting block {i + 1}/{len(blockList)}")
        cipher1 = encrypt1(blockList[i], iv)
        cipher2 = encrypt1(cipher1, key)
        list_of_ciphers.append(cipher2)
        iv = cipher2
    print(f"[INFO] Message encryption complete")
    return list_of_ciphers


def decrypt1(cipher, key):
    return bytearray(cipher[i] ^ key[i] for i in range(len(cipher)))


def decrypt_cipher(list_cipher, key, iv):
    print(f"[INFO] Starting decryption")
    list_of_decrypted_blocks = []
    for i in range(len(list_cipher)):
        if (i+1) % 10 == 0:
            print(f"[LOG] Decrypting block {i + 1}/{len(list_cipher)}")
        temp = decrypt1(list_cipher[i], key)
        plain = decrypt1(temp, iv)
        list_of_decrypted_blocks.append(plain)
        iv = list_cipher[i]
    print(f"[INFO] Decryption complete")
    return b''.join(list_of_decrypted_blocks)


###########################
# Gestion des fichiers
def BreakFile(file_bytes, len_of_block):
    print(f"[LOG] Breaking file into blocks of size {len_of_block}")
    list_of_blocks = []
    padding_needed = len_of_block - (len(file_bytes) % len_of_block)
    file_bytes += bytes([padding_needed]) * padding_needed  # Padding PKCS#7

    for i in range(0, len(file_bytes), len_of_block):
        block = file_bytes[i:i + len_of_block]
        list_of_blocks.append(bytearray(block))
    print(f"[LOG] File divided into {len(list_of_blocks)} blocks")
    return list_of_blocks


###########################
# Chiffrement de texte
def encrypt_text(message):
    print(f"[INFO] Encrypting text message {message}")
    message_bytes = message.encode('utf-8')
    len_of_block = 8
    blockList = BreakFile(message_bytes, len_of_block)
    key = GenKey(len_of_block)
    iv = GenKey(len_of_block)
    cipher_list = encrypt_message(blockList, key, iv)
    encrypted_text = b''.join(cipher_list)
    with open('text.enc', 'wb') as f_out:
        original_size = len(encrypted_text)
        f_out.write(original_size.to_bytes(4, 'big'))
        for cipher in cipher_list:
            f_out.write(cipher)
    print(f"[SUCCESS] Text message encrypted and saved to 'text.enc'")
    return encrypted_text, key.hex(), iv.hex()


#def decrypt_text2(encrypted_text, key, iv):
#    print("[INFO] Decrypting text message")
#    len_of_block = 8
#    cipher_bytes = bytes.fromhex(encrypted_text)
#    blockList = BreakFile(cipher_bytes, len_of_block)
#    key = bytearray.fromhex(key)
#    iv = bytearray.fromhex(iv)
#    decrypted_bytes = decrypt_cipher(blockList, key, iv)
#    padding_length = decrypted_bytes[-1] # Removal of Padding PKCS#7
#    decrypted_message = decrypted_bytes[:-padding_length].decode('utf-8')
#    #decrypted_message = decrypted_message.decode('utf-8')
#    print("[SUCCESS] Text message decryption complete")
#    return decrypted_message

def decrypt_text(file_path, key, iv):
    print(f"[INFO] Decrypting file: {file_path}")
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
    print(f"[SUCCESS] File decrypted and saved to '{output_file}'")
    print(f"\nDecrypted message : {decrypted_bytes} \n\n")
    messagebox.showinfo("Success", f"Decrypted message: {decrypted_bytes}")

###########################
# Chiffrement de fichiers
def encrypt_file(file_path):
    print(f"[INFO] Encrypting file: {file_path}")
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
    print(f"[SUCCESS] File encrypted and saved to '{file_path}.enc'")
    return key.hex(), iv.hex()


def decrypt_file(file_path, key, iv):
    print(f"[INFO] Decrypting file: {file_path}")
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
    print(f"[SUCCESS] File decrypted and saved to '{output_file}'")


###########################
# Interface Utilisateur
def custom_ask_string(title, prompt):
    def on_confirm():
        nonlocal result # Accède à la variable result depuis la fonction mère.
        result = entry.get()  
        dialog.destroy()  

    result = None  

    
    dialog = tk.Toplevel()  
    dialog.title(title)  
    dialog.geometry("300x150")  
    dialog.attributes('-topmost', True)  # Force la fenêtre à rester au premier plan
    dialog.grab_set()  # Bloque les interactions avec les autres fenêtres

    
    tk.Label(dialog, text=prompt).pack(pady=10)  # Ajoute un label pour le texte d'invite
    entry = tk.Entry(dialog)  # Champ de saisie
    entry.pack(pady=5)  # Ajoute le champ de saisie
    confirm_button = tk.Button(dialog, text="Confirmer", command=on_confirm)  # Bouton pour valider
    confirm_button.pack(pady=10)  # Ajoute le bouton "Confirmer"

    dialog.wait_window()  # Bloque l'exécution jusqu'à la fermeture de la fenêtre
    return result  


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
                print(f"[SUCCESS] Encryption complete for file: {file_path}")
                print(f"Key : {key}")
                print(f"IV : {iv}")
                messagebox.showinfo("Success", f"Key: {key}\nIV: {iv}")
        else:
            message = simpledialog.askstring("Input", "Enter your message to encrypt:")
            if message:
                cipher, key, iv = encrypt_text(message)
                print("[SUCCESS] Text encryption complete")
                print(f"\nEncrypted message : {cipher} \n\n")
                print(f"Key : {key}")
                print(f"IV : {iv}")
                messagebox.showinfo("Success", f"Key: {key}\nIV: {iv}")

    select_option()


def decrypt():
    
    def select_option():
        choice = messagebox.askyesno(
            "Type de déchiffrement",
            "Voulez-vous déchiffrer un fichier ? (Oui = fichier, Non = fichier texte)"
        )
        if choice:
            file_path = filedialog.askopenfilename(title="Select File to Decrypt")
            if file_path:
                key = custom_ask_string("Key Input", "Enter Key (hex):")
                iv = custom_ask_string("IV Input", "Enter IV (hex):")
            if key and iv:
                decrypt_file(file_path, key, iv)
                print(f"[SUCCESS] Decryption complete for file: {file_path}")
                messagebox.showinfo("Success", f"File decrypted and saved as '{file_path.replace('.enc', '_decrypted')}'")
        else:
            file_path = filedialog.askopenfilename(title="Select File to Decrypt")
            if file_path:
                key = custom_ask_string("Key Input", "Enter Key (hex):")
                iv = custom_ask_string("IV Input", "Enter IV (hex):")
                if key and iv:
                    message = decrypt_text(file_path,key,iv)
                    print("[SUCCESS] Text decryption complete")
                    

    select_option()

###########################
def main():
    main_window = tk.Tk()
    main_window.title("CryptBC")
    main_window.geometry("300x200")

    welcome_label = tk.Label(main_window, text="Welcome to CryptBC!")
    welcome_label.pack(pady=20)

    button_frame = tk.Frame(main_window)
    button_frame.pack(pady=10)

    encrypt_button = tk.Button(button_frame, text="Encrypt", command=encrypt)
    encrypt_button.pack(side=tk.LEFT, padx=10)

    decrypt_button = tk.Button(button_frame, text="Decrypt", command=decrypt)
    decrypt_button.pack(side=tk.LEFT, padx=10)

    main_window.mainloop()


###########################

main()

# CBC_XOR v2.4

# Ajouts :
#    
# Modifications :
#    - Patch du Padding PCKS7