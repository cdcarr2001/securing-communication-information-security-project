##
# stream_cipher.py
# Connor Carr
# 11/15/24
##

import sys
from secrets import token_hex
from prb import Prb

def run(args: list) -> None:
    '''
    Runs the stream cipher from the command line when fed with the command line arguments
    
    Args:
        args (list): arguments from the command line
    '''

    # Determine if there are even enough arguments to run an operation
    if len(args) < 4:

        print("Usage: python stream_cipher.py <g|e|d>")
        exit()

    args = args[1:] # Removes the first item of the arguments as it is not needed
    mode = args[0]
    flags = get_flags(args[1:])
    file = flags["out_file"]
    keystream = start_keystream(flags["key"])

    # Get output from if tree
    if mode == "g": # generate

        if "out_file" not in flags:

            print("Usage: python stream_cipher.py g -o <output file>")
            exit()

        output = generate_key()

    elif mode == "e": # encrypt

        if "key" not in flags or "input" not in flags:

            print("Usage: python stream_cipher.py e -k <key file> -f <input file> -o " +
                    "<output file>")
            exit()

        output = encrypt_whole(flags["input"], keystream)

    elif mode == "d": # decrypt

        if "key" not in flags or "input" not in flags:

            print("Usage: python stream_cipher.py d -k <key file> -f <input file> -o " +
                    "<output file>")
            exit()

        output = decrypt_whole(flags["input"], keystream)

    else:

        print("Usage: python stream_cipher.py <g|e|d>")
        exit()

    # Write the output to file
    file.write(output)
    # Close file for good measure
    file.close() 

def get_flags(args: list) -> dict:
    '''
    Parse command line arguments to get the flags from them

    Args:
        args (list): command line arguments including flags
    
    Returns:
        dict: dictionary containing relevant flags and values
    '''

    index = 0
    flags = {}

    while index <= len(args) - 1:
        
        if args[index] == "-k": # key

            try:

                flags['key'] = open(args[index + 1], "r").read()

            # Incase file is not found
            except(FileNotFoundError):
                
                print("Key file not found")
                exit(1)

        elif args[index] == "-f": # input file

            try:

                flags['input'] = open(args[index + 1], "r").read()

            # Incase file is not found
            except(FileNotFoundError):
                
                print("Input file not found")
                exit(1)

        elif args[index] == "-o": # output file

            try:

                flags['out_file'] = open(args[index + 1], "x")

            # incase the file already exists
            except(FileExistsError):

                flags['out_file'] = open(args[index + 1], "w")

        index += 2

    return flags

def start_keystream(key: str) -> Prb:
    '''
    Starts the keystream to allow for decryption

    Args:
        key (str): Key string

    Returns:
        Prb: keystream
    '''

    return Prb(key)

def generate_key() -> str:
    '''
    Generates and returns a 8 byte hexadecimal key.
    
    Returns:
        str: 8 byte hexadecimal string
    '''

    return token_hex(8)

def encrypt_whole(input: str, keystream: Prb) -> str:
    '''
    Encrypts the input and returns it as hexadecimal

    Args:
        input (str): String to be encrypted
        keystream (Prb): Keystream

    Returns:
        str: Encrypted input string as hexadecimal
    '''

    # Output of the encryption
    output = ""

    for char in input:

        output += encrypt_one(char, keystream)

    return output

def encrypt_one(input: str, keystream: Prb) -> str:
    '''
    Encrypts one character

    Args:
        input (str): character as string
        keystream (Prb): keystream
    
    Returns:
        str: character encrypted as hexademical
    '''

    # Check if keystream has been initalized
    if keystream == None:

        raise ValueError("Keystream was never initalized")
    # Check input length
    if len(input) > 1:

        raise ValueError("Input is longer than one character")

    # Keystream Byte
    ksb = keystream.next_byte()
    # Input as byte
    char_byte = ord(input)
    # Input XORed with Keystream Byte
    xored_byte = (ksb ^ char_byte)

    # Create and append the XORed byte to the byte array
    ba = bytearray()
    ba.append(xored_byte)

    return ba.hex()

def decrypt_whole(input: str, keystream: Prb) -> str:
    '''
    Decrypts the input and returns it as a string

    Args:
        input (str): Hexadecimal to be decrypted
        keystream (Prb): keystream
    
    Returns:
        str: Decrypted input as string
    '''

    # Output of the decryption
    output = ""
    index = 0

    # While index is less than the input length
    while index < len(input) - 1:

        # Get the hexadecimal from the input
        hd = input[index:index + 2]

        # Decrypt the hexadecimal to plain text and add to the output
        output += decrypt_one(hd, keystream)

        # Increment by 2 to reach the next hexadecimal
        index += 2

    return output

def decrypt_one(input: str, keystream: Prb) -> str:
    '''
    Decrypts one character
    
    Args:
        input (str): character encrypted as hexadecimal
        keystream (Prb): keystream
    
    Returns:
        str: decrypted character as string
    '''
    
    # Check if keystream has been initalized
    if keystream == None:

        raise ValueError("Keystream was never initalized")
    # Check if the input is a 2 digit hexadecimal value
    if len(input) != 2:

        raise ValueError("Input is not 2 hexadecimal values")

    # Key Stream Byte
    ksb = keystream.next_byte()
    # Plaintext XORed with Keystream byte 
    xored_byte = bytes.fromhex(input)[0]
    # XOR encrypted byte with Keystream byte to get plaintext byte and cast to character
    char_byte = chr(ksb ^ xored_byte)

    return char_byte

# Calls the main function
if __name__ == "__main__":

    run(sys.argv)