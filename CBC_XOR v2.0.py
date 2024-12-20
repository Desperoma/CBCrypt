import tkinter as tk
from tkinter import filedialog, messagebox
from os import urandom

###########################

def GenKey(lenght):
    return bytearray( urandom(lenght) )

###########################

def encrypt1(plain_block, key) :
    return bytearray( ord( plain_block[i] ) ^ key[i] for i in range( len(plain_block) ) )

###########################

def encrypt2(plain_block, key):
    return bytearray( plain_block[i] ^ key[i] for i in range( len(plain_block) ) )

###########################

def encrypt_message(blockList, key, iv, len_of_block):
    list_of_ciphers = []
    for i in range( len(blockList) ):
        cipher1 = encrypt1(blockList[i], iv)
        cipher2 = encrypt2(cipher1, key)
        list_of_ciphers.append( cipher2 )
        iv = cipher2
    return list_of_ciphers

###########################

def decrypt1( cipher, key):
    return bytearray( cipher[i] ^ key[i] for i in range( len(cipher) ) )

###########################

def decrypt2(  cipher, key ):
    return [ chr(cipher[i] ^ key[i]) for i in range( len(cipher) ) ]

###########################

def decrypt_cipher(list_cipher, key, iv):
    #list_of_decrypted_blocks = []
    #for i in range( len(list_cipher) ):
    #    if i == 0:
    #        temp = decrypt1( list_cipher[i], key)
    #        plain = decrypt2(temp, iv)
    #    else:
    #        temp = decrypt1(list_cipher[i], key)
    #        plain = decrypt2(temp, list_cipher[i-1])
    #    list_of_decrypted_blocks.append(plain)
    #return list_of_decrypted_blocks

    list_of_decrypted_blocks = []
    for i in range( len(list_cipher) ):
       temp = decrypt1( list_cipher[i], key)
       plain = decrypt2(temp, iv)
       list_of_decrypted_blocks.append(plain)
       iv = list_cipher[i]
    return list_of_decrypted_blocks

###########################

def BreakMessage(message, len_of_block):
    list_of_blocks = []
    for i in range(0, len(message), len_of_block):
        block = message[i:i+len_of_block]
        if ( len(block) == len_of_block ):
            list_of_blocks.append( block )
        else:
            c = len_of_block - len(block)
            for i in range(c):
                block = block + " "
            list_of_blocks.append(block)
    return list_of_blocks

###########################

def encrypt_ini(myMessage):
    key_iv = {"key" : "" , "iv" : ""}
    len_of_block = 8
    blockList = BreakMessage(myMessage, len_of_block)

    key = GenKey(len_of_block)
    str_key = str(key)
    str_key = str_key[12:-2]
    print("\n")
    print("Key : ", str_key)
    print("\n")
    key_iv["key"] = str_key

    iv = GenKey(len_of_block)
    str_iv = str(iv)
    str_iv = str_iv[12:-2]
    print("IV : ", str_iv)
    print("\n")
    key_iv["iv"] = str_iv

    cipher_list = encrypt_message(blockList, key, iv, len_of_block)

    with open("the_cipher.bin", 'wb') as f_out:
        for cipher in cipher_list:
            f_out.write(cipher + b"\n")  # Save cipher blocks in binary mode
    
    print("The cipher has been inserted in the file 'the_cipher.bin'")
    print("\n")

    return key_iv

###########################

def get_file():
    
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'r') as f_in :
            Content = f_in.read()
    
    return Content

###########################

def message_input():

    def retrieve_input():
        myMessage = entry_message.get("1.0", "end-1c") 
        if not myMessage:
            messagebox.showwarning("Warning", "Please enter a message")
            return
        
        key_iv = encrypt_ini(myMessage)
        
        entry_message.delete("1.0", "end")
        entry_message.insert("1.0"," Key : " + key_iv["key"] + "\n" + "IV : "+ key_iv["iv"])  
        messagebox.showinfo("The message has been encrypted correctly","The cipher has been inserted in the file 'the_cipher.bin'.")
        mesinput.destroy()

    mesinput = tk.Tk()
    mesinput.title("Message input")

    label = tk.Label(mesinput, text="Enter your message :")
    label.pack()

    entry_message = tk.Text(mesinput, height=10, width=50)
    entry_message.pack(pady=10)

    use_button = tk.Button(mesinput, text="Use", command=retrieve_input)
    use_button.pack()

    mesinput.mainloop()

###########################

def encrypt():


    def inpfor():
        enc.destroy()
        message_input()
        return

    def filefor():
        enc.destroy()
        myMessage = get_file()
        myMessage = myMessage.replace("\n", "")
        key_iv = encrypt_ini(myMessage)
        messagebox.showinfo("Succes", "The cipher has been inserted in the file 'the_cipher.bin'")
        messagebox.showinfo("Key :", key_iv["key"])
        messagebox.showinfo("IV :", key_iv["iv"])
        return

    enc = tk.Tk()
    enc.title("Encryption")
    enc.geometry("300x200")

    format_label = tk.Label(enc, text=" Which way do you want to select your message ?")
    format_label.pack(pady = 10)

    file_format = tk.Button(enc, text="Encrypt message from a .txt file", command = filefor)
    file_format.pack(pady = 5)

    input_format = tk.Button(enc, text="Type the message", command = inpfor)
    input_format.pack(pady = 5)

    enc.mainloop()  

    
            
###########################

def decrypt():

    def retrieve_key():
        key = entry_message.get("1.0", "end-1c")
        key = bytearray(eval(f"b'{key}'"))
        if key == bytearray(b'0'):
            messagebox.showwarning("Warning", "Please enter a key")
            return
        entry_message.delete("1.0", "end")
        return key

    def retrieve_iv():
        iv = entry_message.get("1.0", "end-1c") 
        iv = bytearray(eval(f"b'{iv}'"))
        if iv == bytearray(b'0'):
            messagebox.showwarning("Warning", "Please enter an IV")
            return      
        entry_message.delete("1.0", "end")
        return iv
        
    key = bytearray(b'0')
    iv = bytearray(b'0')
    dec = tk.Tk()
    dec.title("Decryption")
    dec.geometry("300x200")

    cipher_list = get_file().split("\n")

    label = tk.Label(dec, text="Enter your Key :")
    label.pack()

    entry_message = tk.Text(dec, height=10, width=50)
    entry_message.pack(pady=10)

    use_button = tk.Button(dec, text="Use", command=retrieve_key)
    use_button.pack()

    label = tk.Label(dec, text="Enter your IV :")
    label.pack()

    entry_message = tk.Text(dec, height=10, width=50)
    entry_message.pack(pady=10)

    use_button = tk.Button(dec, text="Use", command=retrieve_iv)
    use_button.pack()

    decrypted_list = decrypt_cipher(cipher_list,key,iv)
    decrypted_message = ''.join([''.join(block) for block in decrypted_list])

    messagebox.showinfo(" The message is : " + decrypted_message)
    dec.destroy()

    dec.mainloop() 
    
###########################

def main():

    def encr():
        main_window.destroy()
        encrypt()
        return
    
    def decr():
        main_window.destroy()
        decrypt()
        return

    main_window = tk.Tk()
    main_window.title("CryptBC")
    main_window.geometry("300x200")

    welcome_label = tk.Label(main_window, text="Welcome to CryptBC !")
    welcome_label.pack()

    encrypt_button = tk.Button(main_window, text="Encrypt", command=encr)
    encrypt_button.pack(side=tk.LEFT, padx=10)

    decrypt_button= tk.Button(main_window, text="Decrypt", command=decr)
    decrypt_button.pack(side=tk.LEFT, padx=10)

    main_window.mainloop()


###########################

main()


#myMessage = "this is a message 1234567890987654321azertyu!@#{15145iop gdfsgsfefe"


#CBC_XOR v2.0

# Ajouts :
#   - Introduction des fonctions pour gérer l'entrée de messages via une interface graphique (messagebox, simpledialog).
#   - Meilleure gestion de l'interface utilisateur pour le chiffrement et le déchiffrement.
#   - Ajout d'une méthode pour découper des messages en blocs de taille fixe.
#   - Simplification des processus d'encryptage et de décryptage.
# Modifications :
#   - Suppression de commentaires inutiles et consolidation du code en blocs fonctionnels.