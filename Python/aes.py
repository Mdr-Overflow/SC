# open 2 param
# input file
# cripted message to output file

import sys

from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def _checkIfUnicode(data):
    if isinstance(data, str):
        try:
            return data.encode('ascii')
        except UnicodeEncodeError:
            pass
        raise ValueError("Des can only work with encoded strings, not Unicode.")
    return data


# mode = daca cheia se genereaza aleator sau din ce dam noi
def doAES(pathIN, pathOUT, mode):
    file_to_encrypt = pathIN
    #  buffer_size = 65536  # 64kb
    key = get_random_bytes(32)

    print("Cheia este, in hex : " + key.hex())
    # BLOCK_SIZE = 32  # Bytes

    # Genereaza cheia

    if mode == "random":
        pass  # Se va folosi cheia generata random ca valoare initiala
    elif mode == "cliInput":
        print("Scrie-ti cheia pe care doriti sa o utilizati \n")
        key = input("Reminder, cheia trebuie sa fie de 256 de biti , daca nu este de atat se va lua random \n "
                    + " Introduce-ti cheia : ")
        if _checkIfUnicode(key):  # Verificam daca nu contine caractere dubioase
            if len(key.encode('utf-8')) == 32:  # Daca are 32 de bytes putem proceda
                pass
            else:
                key = get_random_bytes(32)

        else:
            key = get_random_bytes(32)
    else:
        pass

    # ### Cripteaza ###

    # Open the input and output files
    try:
        input_file = open(file_to_encrypt, 'rb')
    except OSError:
        print(
            "Could not open/read file:", file_to_encrypt)
        sys.exit()

    if pathOUT is None:
        output_file = open(file_to_encrypt + '_OUT.txt', 'w')
    else:
        output_file = open(pathOUT, 'w')

    plaintext = input_file.read()

    padded_plaintext = pad(plaintext, AES.block_size)

    # Create the cipher object and encrypt the data
    cipher_encrypt = AES.new(key, AES.MODE_ECB)  # ECB = MODEL STANDARD
    ciphertext = cipher_encrypt.encrypt(padded_plaintext)
    try:
        output_file.write(ciphertext.hex())
    except OSError:
        print(
            "Could not open/write to file:", file_to_encrypt)
        sys.exit()

    # Close the input and output files
    input_file.close()
    output_file.close()


if __name__ == "__main__":
    print("AES")
    mode = input("Introduceti modul de obtinere a cheii: " + " 'random' (cel mai sigur) sau 'cliInput' , mod : ")
    pathIn = input("Introduceti calea catre fisierul de input,! calea absoluta sau relativa !, Input : ")
    pathOut = input("Introduceti calea catre fisierul de output,daca scrie-ti 'None' se va creea cu aceelasi nume ca "
                    "cel de input, Output : ")
    if pathOut == 'None':
        pathOut = None

    doAES(pathIn, pathOut, mode)
