##
# Author:  Connor Carr, Andrew Scott and Mark Holliday 
# Version: Fall 2024
# Description: The provided code for project 1 of CS325. 
# Remember to properly document this module with proper documentation strings 
# for the module and each function.
##
import os
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP as rsa_cipher
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15 as sign_alg
from Crypto.Util.Padding import pad, unpad
from stream_cipher import start_keystream, encrypt_whole, decrypt_whole

FILES_DIR = "files/"#Where the text files are intended to be placed.
'''Files directory'''
MY_KEYS_DIR = "my_key_pairs/"#Location of private keys
'''Key pairs directory'''
PUBLIC_KEYS_DIR = "public_keys/"#Location of public keys
'''Public keys directory'''
SHARED_KEYS_DIR = "shared_keys/"#Location of shard keys
'''AES keys directory'''
RSA_EXTN = ".rsa"#RSA key file extension
'''File extension of RSA keys'''
AES_EXTN = ".aes"#AES key file extension
'''File extension of AES keys'''

#See https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/rsa-encryption-maximum-data-size/
RSA_KEY_SIZE = 2048  #4096 Slow #8192 impossibly slow
'''Size of RSA key'''
IV_SIZE = 16
'''Size of IV'''
DIGEST_POINTS = {"start" : 0, "end": 32}
'''Start and end of digest in encrypted file'''
IV_POINTS = {"start": 32, "end": 48}
'''Start and end of IV in encrypted file'''
DATA_POINTS = {"start": 48}
'''Start of data in encrypted file'''
SIGNATURE_POINTS = {"start": 0, "end": 256}
'''Start and end of signature in encrypted key'''
KEY_POINTS = {"start": 256}
'''Start of encrypted key'''

# Prompt functions

def file_prompt(prompt: str) -> str:
    '''
    (Helper function)
    Prompts the user for the given file in the file directory

    Args:
        prompt (str): prompt text

    Returns:
        str: file name with directory

    Raises:
        FileNotFoundError: if file does not exist
    '''

    # Display files
    print(prompt)
    list_files()

    # Prompt for file
    file_name = input("\nEnter choice (include file extension)> ")
    file = FILES_DIR + file_name

    # Test if file does not exist
    if (not os.path.isfile(file)):

        # Print that the file does not exist
        print(f"\nFile with the name {file_name} does not exist.")
        
        raise FileNotFoundError
    
    # Return file
    return file

def key_prompt(prompt: str, dir: str) -> str:
    '''
    (Helper function)
    Prompts the user for the name of a key in the given directory

    Args:
        prompt (str): prompt text
        dir (str): directory of the key

    Returns:
        str: key name + directory

    Raises:
        ValueError: if the directory is not correct
        FileNotFoundError: if the key file does not exist
    '''
    
    # Display keys
    print(prompt)
    # If looking for aes keys
    if (dir == SHARED_KEYS_DIR):

        list_shared_keys()
    # If looking for public keys
    elif (dir == PUBLIC_KEYS_DIR):

        list_public_keys()
    # If looking for private keys
    elif(dir == MY_KEYS_DIR):

        list_own_key_pairs()
    # Otherwise
    else:

        # Make the error known
        print("Invalid directory")
        raise ValueError

    # Prompt for key
    key_name = input("\nEnter choice (include file extension)> ")
    key = dir + key_name

    # Test if key does not exist
    if (not os.path.isfile(key)):

        # Print that the key does not exist
        print(f"\nKey with the name {key_name} does not exist.")
        
        raise FileNotFoundError
    
    # Return key
    return key

def output_prompt(dir: str) -> str:
    '''
    (Helper function)
    Prompts the user for the output file name

    Args:
        dir (str): directory the file should be placed

    Returns:
        str: file name + directory

    Raises:
        FileExistsError: if file with same name already exists
    '''

    # Prompt for file name to save to
    out_name = input("\nEnter file name (include file extension) to save> ")
    out = dir + out_name

    # Test if output file already exists
    if (os.path.isfile(out)):

        # Print that the chosen file name already exists
        print(f"Output file with the name {out_name} already exists.")
        
        raise FileExistsError
    
    # Return output
    return out

# Make key functions

def make_rsa_keys() -> None:
    '''
    Generates and saves a RSA Key Pair (Private and Public) to the "my_key_pairs/" directory
    based on user input
    '''

    # Prompt user for file name to save keys as
    name = input("\nEnter the name for the keys (Do not include file name)> ")

    # Private file directory and name
    private_file = f"{MY_KEYS_DIR}/{name}_prv.rsa"
    # Public file directory and name
    public_file = f"{MY_KEYS_DIR}/{name}_pub.rsa"

    # Test if either of the key files already exists
    if (os.path.isfile(private_file) or os.path.isfile(public_file)):

        # Print that the key files already exist
        print(f"\nKey files with the name {name} already exist.")
    # If the key files do not already exist
    else:

        # Generate a key with the predefined key size
        key = RSA.generate(RSA_KEY_SIZE)
        # Export the private key
        private_key = key.export_key(format = "PEM")
        # Export the public key
        public_key = key.public_key().export_key(format = "PEM")

        # Create and open the private file in bytes mode
        with open(private_file, "xb") as f:

            # Write the private key to the file
            f.write(private_key)

        # Create and open the public file in bytes mode
        with open(public_file, "xb") as f:

            # Write the public key to the file
            f.write(public_key)

def make_aes_key() -> None:
    '''
    Generates and saves an AES key to the "shared_keys/" directory based on user input
    '''

    # Prompt user for file name to save keys as
    name = input("Enter the name for the key (Do not include file extension)> ")
    
    # File name and directory
    file = f"{SHARED_KEYS_DIR}/{name}.aes"

    # Prompt user for number of bits the key should be
    bits = input("\nHow many bits should the key be (128, 192, 256)> ")

    # Test if the key file already exists
    if (os.path.isfile(file)):

        # Print that the key file already exist
        print(f"\nKey file with the name {name} already exist.")
    # Test if the number of bits is valid
    elif (bits not in ["128", "192", "256"]):

        # Print that the number of bits is invalid
        print(f"\nNumber of bits is not valid.")
    # If the key file does not already exist and the number of bits is valid
    else:

        # Get random bytes of the length bits / 8
        key = Random.get_random_bytes(int(bits) // 8)

        # Create and open the file in bytes mode
        with open(file, "x") as f:

            # Write the AES key to the file
            f.write(bytes.hex(key))

# List functions

def list_from_dir(directory: str, header: str = None, extension: str = None) -> None:
    '''
    (Helper function)
    Lists all files in the given directory
    
    Args:
        directory (str): directory to list files from
        header (str): header text to display
        extension (str): file extension to display
    '''

    # Print header
    print(f"======{header}=======")

    # For each file in the files directory
    for file in os.listdir(directory):

        # If the extension is not specified or the extension matches
        if ((extension == None) or (file[-4:] == extension)):

            # Print the file
            print(file)

def list_files() -> None:
    '''Lists all files in the "files/" directory'''

    list_from_dir(FILES_DIR, "Files")

def list_own_key_pairs() -> None:
    '''Lists all files in the "my_key_pairs/" directory'''

    list_from_dir(MY_KEYS_DIR, "Own Key Pairs", RSA_EXTN)

def list_public_keys() -> None:
    '''Lists all files in the "public_keys/" directory'''

    list_from_dir(PUBLIC_KEYS_DIR, "Other’s Public Keys", RSA_EXTN)

def list_shared_keys() -> None:
    '''Lists all files in the "shared_keys/" directory'''

    list_from_dir(SHARED_KEYS_DIR, "Shared Keys", AES_EXTN)

# AES functions

def encrypt_aes() -> None:
    '''
    Encrypts a file with an AES key and writes it to an output file, all based on user input
    '''

    try:
        
        # Get input file
        file = file_prompt("Choose the file you want to encrypt")
        # Get secret key
        key = key_prompt("\nChoose the shared AES key you want to use", SHARED_KEYS_DIR)
        # Get output file
        out = output_prompt(FILES_DIR)
    except FileNotFoundError or FileExistsError:

        # Return to menu
        return
    
    # Read the file in as bytes
    with open(file, "rb") as f:

        # Read file in
        data = f.read()
    
    # Read the key in
    with open(key, "r") as f:

        # Read key in
        key = bytes.fromhex(f.read())

    # Pad out the data to match the AES block size
    data = pad(data, AES.block_size)

    # Create a digest of the file
    digest = SHA256.new(data).digest()

    # Get random 16 byte IV
    iv = Random.get_random_bytes(IV_SIZE)

    try:

        cipher = AES.new(mode = AES.MODE_CBC, key = key, iv = iv)
    # Happens when key is of wrong length
    except ValueError:

        # Print error message
        print("\nWrong key length. Key may be encrypted.")
        # Return to menu
        return

    # Cipher text
    cipher_text = cipher.encrypt(data)

    # Create and write to the output file
    with open(out, "x") as f:

        # Write the digest as hexadecimal
        f.write(bytes.hex(digest))
        # Write the IV as hexadecimal
        f.write(bytes.hex(iv))
        # Write the cipher text as hexadecimal
        f.write(bytes.hex(cipher_text))

def decrypt_aes() -> None:
    '''
    Decrypts a file with an AES key and writes it to an output file, all based on user input
    '''

    try:
        
        # Get input file
        file = file_prompt("Choose the file you want to decrypt")
        # Get secret key
        key = key_prompt("\nChoose the shared AES key you want to use", SHARED_KEYS_DIR)
        # Get output file
        out = output_prompt(FILES_DIR)
    except FileNotFoundError or FileExistsError:

        # Return to menu
        return
    
    # Read in relevant parts of file
    with open(file, "r") as f:

        # Make sure the file was actually encrypted by this program
        try:

            # Read the file to raw
            raw = bytes.fromhex(f.read())
        # Happens when file is not in hexadecimal, meaning it was not encrypted by this program
        except ValueError:

            # Print an error message
            print(f"\nThe file {file[6:]} was not encrypted by this program.")
            # Return to menu
            return
        
        # Get digest
        digest = raw[DIGEST_POINTS["start"]:DIGEST_POINTS["end"]]
        # Get IV from split string and convert to bytes
        iv = raw[IV_POINTS["start"]:IV_POINTS["end"]]
        # Get encrypted data from split string and convert to bytes
        data = raw[DATA_POINTS["start"]:]

    # Read in key
    with open(key, "r") as f:

        key = bytes.fromhex(f.read())

    # Create cipher from key and IV
    try:

        cipher = AES.new(mode = AES.MODE_CBC, key = key, iv = iv)
    # Happens when key is of wrong length
    except ValueError:

        # Print error message
        print("\nWrong key length. Key may be encrypted.")
        # Return to menu
        return

    # Decrypt the data
    decrypted_data = cipher.decrypt(data)

    # Create a digest of the decrypted data to compare to previous digest
    new_disgest = SHA256.new(decrypted_data).digest()

    # Check if the digests do not match
    if (digest != new_disgest):

        # Print a warning
        print("\nDigests do not match.\n")
        # Display digests
        print(f"Old: {bytes.hex(digest)}\nNew: {bytes.hex(new_disgest)}")
    # Otherwise write to file
    else:

        # Unpad the data
        decrypted_data = unpad(decrypted_data, AES.block_size)

        # Create and open output file
        with open(out, "x") as f:

            # Write decrypted data to output file
            f.write(decrypted_data.decode())  

# Stream cipher functions

def encrypt_stream() -> None:
    '''
    Encrypt a file using a stream cipher (updated from project one) and write it to an output file
    based on user input
    '''

    # Call stream_helper in encrypt mode
    stream_helper("encrypt")

def decrypt_stream() -> None:
    '''
    Decrypt a file using a stream cipher (updated from project one) and write it to an output file
    based on user input
    '''

    # Call stream_helper in decrypt mode
    stream_helper("decrypt")

def stream_helper(mode: str) -> None:
    '''
    (Helper function)
    Encrypt or decrypt a file using a stream cipher (updated from project one) and write it to an
    output file based on user input

    Args:
        mode (str): "encrypt" or "decrypt"

    Raises:
        ValueError: If mode is not "encrypt" or "decrypt"
    '''

    # Check mode validity
    if (mode not in ["encrypt", "decrypt"]):

        raise ValueError("Mode is not valid")

    # Get files
    try:
        
        # Get input file
        file = file_prompt(f"Choose the file you want to {mode}")
        # Get secret key
        key = key_prompt(f"\nChoose the key you want to use to {mode}", SHARED_KEYS_DIR)
        # Get output file
        out = output_prompt(FILES_DIR)
    except FileNotFoundError or FileExistsError:

        # Return to menu
        return
    
    # Read files

    # Read in the input file
    with open(file, "r") as f:

        data = f.read()

    # Read in the key
    with open(key, "r") as f:

        key_data = f.read()

    # Start work

    # Get keystream
    keystream = start_keystream(key_data)

    # If mode is encrypt
    if (mode == "encrypt"):

        # Encrypt the data
        modified_data = encrypt_whole(data, keystream)
    # If mode is decrypt
    elif (mode == "decrypt"):

        # Try to decrypt the data
        try:

            # Decrypt the data
            modified_data = decrypt_whole(data, keystream)
        # Happens when the file is not in hexadecimal, meaning it was not encrypted
        except ValueError:

            # Print the error
            print(f"\nThe file {file[6:]} was not encrypted by this program.")

            # Return to menu
            return

    # Try to write to file
    try:

        # Write to file
        with open(out, "x") as f:

            f.write(modified_data)
    # Happens when the data cannot be written as unicode, which means the key was incorrect
    except UnicodeEncodeError:

        # Print an error
        print(f"\nCannot decode {file[6:]}, incorrect key.")

        # Cleanup the empty file
        os.remove(out)

        # Return to menu
        return

# RSA functions

def encrypt_aes_key_with_rsa() -> None:
    '''
    Encrypts an AES key with a public RSA key, signs it with a private RSA key, and saves it
    according to user input.
    '''

    # Get files
    try:

        # Get aes file to encrypt
        aes = key_prompt("Choose the AES key you want to encrypt", SHARED_KEYS_DIR)
        # Get the public key to encrypt with
        pub = key_prompt("\nChoose the Public RSA key to use to encrypt", PUBLIC_KEYS_DIR)
        # Get the private key to sign with
        prv = key_prompt("\nChoose the Private RSA key to use to sign", MY_KEYS_DIR)
        # Get the output file
        out = output_prompt(SHARED_KEYS_DIR)
    except FileNotFoundError or FileExistsError:

        # Return to menu
        return
    
    # Read in files

    # Read the AES key in
    with open(aes, "r") as f:

        # Read key in
        aes_key = bytes.fromhex(f.read())

    # Read the public key in
    with open(pub, "r") as f:

        # Read the key in
        pub_key = f.read()
        pub_key = RSA.import_key(pub_key)

    # Read the private key in
    with open(prv, "r") as f:

        # Read key in
        prv_key = f.read()
        prv_key = RSA.import_key(prv_key)

    # Start work

    # Create signer from private key
    signer = sign_alg.new(prv_key)
    # Create cipher from public key
    cipher = rsa_cipher.new(pub_key)

    # Make digest of aes key
    digest = SHA256.new(aes_key)
    # Sign the digest
    signature = signer.sign(digest)
    # Encrypt AES key
    enc_aes = cipher.encrypt(aes_key)

    # Write encrypted key and signature to file
    with open(out, "x") as f:

        # Write signature as hex
        f.write(bytes.hex(signature))
        # Write encrypted key as hex
        f.write(bytes.hex(enc_aes))

def decrypt_aes_key_with_rsa() -> None:
    '''
    Decrypts an AES key with a private RSA key, verifies it with a public RSA key, and saves it
    according to user input.
    '''

    # Get files
    try:
        
        # Get aes file to decrypt
        aes = key_prompt("Choose the AES key you want to decrypt", SHARED_KEYS_DIR)
        # Get the private key to decrypt with
        prv = key_prompt("\nChoose the Private RSA key to use to decrypt", MY_KEYS_DIR)
        # Get the public key to verify with
        pub = key_prompt("\nChoose the Public RSA key to use to verify", PUBLIC_KEYS_DIR)
        # Get the output file
        out = output_prompt(SHARED_KEYS_DIR)
    except FileNotFoundError or FileExistsError:

        # Return to menu
        return
    
    # Read in files

    # Read the AES key in
    with open(aes, "r") as f:

        # Make sure the file was actually encrypted by this program
        try:

            # Read the file to raw
            raw = bytes.fromhex(f.read())
        # Happens when file is not in hexadecimal, meaning it was not encrypted by this program
        except ValueError:

            # Print an error message
            print(f"\nThe key {aes[11:]} was not encrypted by this program.")
            # Return to menu
            return
        
        # Get digest
        signature = raw[SIGNATURE_POINTS["start"]:SIGNATURE_POINTS["end"]]
        # Get encrypted data from split string and convert to bytes
        enc_aes = raw[KEY_POINTS["start"]:]
    # Read the private key in
    with open(prv, "r") as f:

        # Read key in
        prv_key = f.read()
        prv_key = RSA.import_key(prv_key)

    # Read the public key in
    with open(pub, "r") as f:

        # Read the key in
        pub_key = f.read()
        pub_key = RSA.import_key(pub_key)
         
    # Start work

    # Verifier
    verifier = sign_alg.new(pub_key)
    # Create cipher
    cipher = rsa_cipher.new(prv_key)
    
    # Try to decrypt AES key
    try:

        aes_key = cipher.decrypt(enc_aes)
    # If the private key used to decrypt is not the pair of the public used to encrypt
    except ValueError:

        # Print the error
        print("\nUnable to decrypt, incorrect private key used.")
        # Return to menu
        return
    
    # Make a digest of the AES key
    digest = SHA256.new(aes_key)

    # Verify the AES key
    try:

        verifier.verify(digest, signature)

        with open(out, "x") as f:

            f.write(bytes.hex(aes_key))
    # Happens when signature is not verifiable
    except ValueError:

        print("\nSignature could not be verified.")

# Provided functions

def do_option(option) -> None:
    '''Respond to a manu option by calling the appropriate function. If an option 
    that is <= 0 and > 12  or not an int is specified, an error message will be printed.
    Parameters:
        option : (int) The selected option.'''
    if option == '1': #Make keys
        make_rsa_keys()   
    elif option =='2':
        make_aes_key()
    elif option == '3':
        list_files()
    elif option == '4':
        list_own_key_pairs()
    elif option == '5':
        list_public_keys()
    elif option == '6':
        list_shared_keys()
    elif option == '7':
        encrypt_aes()
    elif option == '8':
        decrypt_aes()
    elif option == '9':
        encrypt_stream()
    elif option == '10':
        decrypt_stream()
    elif option == '11':
        encrypt_aes_key_with_rsa()
    elif option == '12':
        decrypt_aes_key_with_rsa()
    elif option != '0':
        print("Error invalid option.")

def menu() -> None:
    print("\n====The Secure Decriptor=====")
    print("1 - Generate RSA Public Private Key Pair")
    print("2 - Generate AES Key")
    print("3 - List files directory")
    print("4 - List Own RSA Key Pairs")
    print("5 - List Other's Public RSA Keys")
    print("6 - List Shared AES Keys")
    print("7 - Symmetric Encryption with AES")
    print("8 - Symmetric Decryption with AES")
    print("9 - Symmetric Encrption with Stream Cipher")
    print("10 - Symmetric Decryption with Stream Cipher")
    print("11 - Asymmetric Key Encryption with RSA")
    print("12 - Asymmetric Key Decryption with RSA")
    print("0 - Exit")

def main() -> None:
    '''Run the program by asking the user to enter an option and then by acting 
    on that option with the enter_option command.'''
    menu()
    option = input("\nEnter Option> ")
    print()
    while option != "0":
        do_option(option)
        menu()
        option = input("\nEnter Option> ")
        print()

    print("Program closed.")

if __name__ == "__main__":
    main()