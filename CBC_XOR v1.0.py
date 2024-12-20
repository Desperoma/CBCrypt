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

    len_of_block = 8
    blockList = BreakMessage(myMessage, len_of_block)

    key = GenKey(len_of_block)
    str_key = str(key)
    str_key = str_key[12:-2]
    print("Key : ", str_key)
    print("\n")

    iv = GenKey(len_of_block)
    str_iv = str(iv)
    str_iv = str_iv[12:-2]
    print("IV : ", str_iv)
    print("\n")

    cipher_list = encrypt_message(blockList, key, iv, len_of_block)

    with open("the_cipher.bin", 'wb') as f_out:
        for cipher in cipher_list:
            f_out.write(cipher + b"\n")  # Save cipher blocks in binary mode
    
    print("The cipher has been inserted in the file 'the_cipher.bin'")

    return 

###########################

def encrypt():

    #myMessage = "this is a message 1234567890987654321azertyuiop gdfsgsfefe"
    encrypt_format = ""

    while encrypt_format != "1" and encrypt_format != "2" and encrypt_format != "0" :
        print("Encrypt message from a .txt file (1)")
        print("Encrypt message by input in terminal (2)")
        print("Menu (0)")
        print("\n")
        encrypt_format = input()
        print("\n")


    if encrypt_format == "1":

        print("Go Back (0)")
        print("\n")

        message_file = input("Path to the .txt file : ")

        print("\n")

        if message_file == "0":
            print("\n")
            print("\n")
            print("\n")
            return encrypt()

        else:

            with open(message_file, 'r') as f_in :
                myMessage = f_in.read()
                myMessage = myMessage.replace("\n", "")
            

    elif encrypt_format == "2":

        print("Go Back (0)")
        print("\n")

        myMessage = input("enter a message to encrypt: ")

        print("\n")

        if myMessage == "0":
            print("\n")
            print("\n")
            print("\n")
            return encrypt()

        

    elif encrypt_format == "0":
        encrypt_format = ""
        print("\n")
        print("\n")
        print("\n")
        return main()
        

    return encrypt_ini(myMessage)
            
###########################

def decrypt():
    cipher_list = []

    print("Go Back (0)")
    print("\n")
    cipher_file = input("Path to the cipher file : ")
    print("\n")

    if cipher_file == "0":
        print("\n")
        print("\n")
        print("\n")
        return main()
    
    else:

        with open(cipher_file, 'rb') as f_in:
            lines = f_in.readlines()
            
            for line in lines:
                cipher_list.append(bytearray(line.strip()))  
        print("Go Back (0)")
        print("\n")
        key = bytearray(eval(f"b'{input("Key : ")}'"))
        print("\n")

        if key == bytearray(b'0'):
            print("\n")
            print("\n")
            print("\n")
            return main()
        
        else:
            print("Go Back (0)")
            print("\n")
            iv = bytearray(eval(f"b'{input("IV : ")}'"))
            print("\n")

            if iv == bytearray(b'0'):
                print("\n")
                print("\n")
                print("\n")
                return main()
        
            else:
            
                decrypted_list = decrypt_cipher(cipher_list, key, iv)

                
                decrypted_message = ''.join([''.join(block) for block in decrypted_list])
                print("Decrypted message:", decrypted_message)
                print("\n")
                print("\n")
                print("\n")

                return 



###########################

def main():

    encrypt_decrypt = ""
    while encrypt_decrypt != "1" and encrypt_decrypt != "2" and encrypt_decrypt != "0" :
        print("\n")
        print("\n")
        print("=== Menu Principal ===")
        print("\n")
        print("Encrypt message (1)")
        print("Decrypt cipher (2)")
        print("Quit (0)")
        print("\n")
        encrypt_decrypt = input()
        print("\n")


    if encrypt_decrypt == "1":
        encrypt_decrypt = ""
        return encrypt()
    
    elif encrypt_decrypt == "2":
        encrypt_decrypt = ""
        return decrypt()
    
    elif encrypt_decrypt == "0":
        encrypt_decrypt = ""
        print("Thank you !")
    
    return


###########################

main()
