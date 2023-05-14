import sys
import six
from functools import reduce

# Modes of crypting / cyphering
ECB = 0

# Modes of padding
PAD_NORMAL = 1


class desP(object):
    def __init__(self, key=None, pad=None, padmode=PAD_NORMAL):
        if pad:
            pad = self._checkIfUnicode(pad)
        self.block_size = 8
        # Sanity checking
        if key is None:
            raise ValueError("Algo necessitates a key")

        if key and len(key) != self.block_size:
            raise ValueError("Invalid Key, must be a multiple of " + str(self.block_size) + " bytes")

        # Set the passed in variables

        self._padding = pad
        self._padmode = padmode

    def getKey(self):
        """getKey() -> bytes"""
        return self.__key

    def setKey(self, key):
        """Will set the crypting key for this object."""
        key = self._checkIfUnicode(key)
        self.__key = key

    def getPadding(self):
        """getPadding() -> bytes of length 1. Padding character."""
        return self._padding

    def setPadding(self, pad):
        """setPadding() -> bytes of length 1. Padding character."""
        if pad is not None:
            pad = self._checkIfUnicode(pad)
        self._padding = pad

    def getPadMode(self):
        """getPadMode() -> pyDes.PAD_NORMAL or pyDes.PAD_PKCS5"""
        return self._padmode

    def setPadMode(self, mode):
        """Sets the type of padding mode, pyDes.PAD_NORMAL or pyDes.PAD_PKCS5"""
        self._padmode = mode

    def _padData(self, data, pad, padmode):
        # Pad data depending on the mode
        if padmode is None:
            # Get the default padding mode.
            padmode = self.getPadMode()

        if padmode == PAD_NORMAL:
            if len(data) % self.block_size == 0:
                # No padding required.
                return data

            if not pad:
                # Get the default padding.
                pad = self.getPadding()
            if not pad:
                raise ValueError("Data must be a multiple of " + str(
                    self.block_size) + " bytes in length. Set the pad character.")
            data += (self.block_size - (len(data) % self.block_size)) * pad

        return data


    def _checkIfUnicode(self, data):
        # Only accept byte strings or ascii unicode values, otherwise
        # there is no way to correctly decode the data into bytes.
        if isinstance(data, str):
            try:
                return data.encode('ascii')
            except UnicodeEncodeError:
                pass
            raise ValueError("Des can only work with encoded strings, not Unicode.")
        return data


class des(desP):
    # Permutation and translation tables for DES
    _pc1 = [56, 48, 40, 32, 24, 16, 8,
            0, 57, 49, 41, 33, 25, 17,
            9, 1, 58, 50, 42, 34, 26,
            18, 10, 2, 59, 51, 43, 35,
            62, 54, 46, 38, 30, 22, 14,
            6, 61, 53, 45, 37, 29, 21,
            13, 5, 60, 52, 44, 36, 28,
            20, 12, 4, 27, 19, 11, 3
            ]

    # number left rotations of pc1
    _left_rotations = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]

    # permuted choice key (table 2)
    _pc2 = [
        13, 16, 10, 23, 0, 4,
        2, 27, 14, 5, 20, 9,
        22, 18, 11, 3, 25, 7,
        15, 6, 26, 19, 12, 1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]

    # initial permutation IP
    _ip = [57, 49, 41, 33, 25, 17, 9, 1,
           59, 51, 43, 35, 27, 19, 11, 3,
           61, 53, 45, 37, 29, 21, 13, 5,
           63, 55, 47, 39, 31, 23, 15, 7,
           56, 48, 40, 32, 24, 16, 8, 0,
           58, 50, 42, 34, 26, 18, 10, 2,
           60, 52, 44, 36, 28, 20, 12, 4,
           62, 54, 46, 38, 30, 22, 14, 6
           ]

    # Expansion table for turning 32 bit blocks into 48 bits
    _E = [
        31, 0, 1, 2, 3, 4,
        3, 4, 5, 6, 7, 8,
        7, 8, 9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31, 0
    ]

    # cutii S
    _sbox = [
        # S1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

        # S2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

        # S3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

        # S4
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

        # S5
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

        # S6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

        # S7
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

        # S8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]

    # 32-bit permutation function P used on the output of the S-boxes
    _p = [
        15, 6, 19, 20, 28, 11,
        27, 16, 0, 14, 22, 25,
        4, 17, 30, 9, 1, 7,
        23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10,
        3, 24
    ]

    # final permutation IP^-1
    _fp = [
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
        32, 0, 40, 8, 48, 16, 56, 24
    ]

    def __init__(self, key, pad=None, padmode=PAD_NORMAL):
        # Sanity checking of arguments.
        #  print(len(bytes(key,"ascii")))
        if len(bytes(key, "ascii")) != 8:  # 8 bytes
            raise ValueError("Invalid DES key size. Key must be exactly 8 bytes long.")
        desP.__init__(self, cheie, pad, padmode)
        self.key_size = 8

        self.L = []
        self.R = []
        self.Kn = [[0] * 48] * 16  # 16 chei de 48-bit (K1 - K16)
        self.final = []

        self.setKey(key)

    def setKey(self, key):
        desP.setKey(self, key)
        self.create_sub_keys()

    def String_to_BitList(self, data):
        data = bytes(data)  # py 3
        l = len(data) * 8
        result = [0] * l
        pos = 0
        for ch in data:
            i = 7
            while i >= 0:
                if ch & (1 << i) != 0:
                    result[pos] = 1
                else:
                    result[pos] = 0
                pos += 1
                i -= 1

        return result

    def String_to_BitList2(self, data):
        data = bytes(data, "ascii")  # py 3
        l = len(data) * 8
        result = [0] * l
        pos = 0
        for ch in data:
            i = 7
            while i >= 0:
                if ch & (1 << i) != 0:
                    result[pos] = 1
                else:
                    result[pos] = 0
                pos += 1
                i -= 1

        return result

    def BitList_to_String(self, data):

        # Transforma lista de biti in string

        result = []
        pos = 0
        c = 0
        while pos < len(data):
            c += data[pos] << (7 - (pos % 8))
            if (pos % 8) == 7:
                result.append(c)
                c = 0
            pos += 1

        return bytes(result)

    def permutare(self, table, block):
        print(block)
        print(table)

        return list(map(lambda x: block[x], table))

    # Transforma cheia data : permutare dupa pc1
    # Creaza 16 subchei, K[1] - K[16]
    def create_sub_keys(self):

        key = self.permutare(des._pc1, self.String_to_BitList(self.getKey()))
        i = 0
        # Split into Left and Right sections (CO, DO)
        self.L = key[:28]
        self.R = key[28:]
        while i < 16:
            j = 0
            # Perform circular left shifts
            while j < des._left_rotations[i]:
                self.L.append(self.L[0])
                del self.L[0]

                self.R.append(self.R[0])
                del self.R[0]

                j += 1

            # Create one of the 16 subkeys through pc2 permutation
            self.Kn[i] = self.permutare(des._pc2, self.L + self.R)

            i += 1

    # criptam prin manipulare de bitit ( shiftare )
    def des_crypt(self, block):

        block = self.permutare(des._ip, block)
        self.L = block[:32]
        self.R = block[32:]

        # De la Kn[1] pana la Kn[16]

        iteration = 0
        iteration_adjustment = 1


        i = 0
        while i < 16:
            # deoarece functia utilizata in pasii de criptare este recurenta ( Rn = Ln-1 + f(Rn-1,Kn) ,
            # Ln = Rn-1) vom salva
            # valoarea  lui R pt. a o asigna la urm. pas
            tempR = self.R[:]

            # Permutate R[i - 1] to start creating R[i]
            self.R = self.permutare(des._E, self.R)

            # Exclusive or R[i - 1] cu K[i], creaza B-urile
            self.R = list(map(lambda x, y: x ^ y, self.R, self.Kn[iteration]))
            B = [self.R[:6], self.R[6:12], self.R[12:18], self.R[18:24], self.R[24:30], self.R[30:36], self.R[36:42],
                 self.R[42:]]

            # Permutarile B[1] to B[8] folosind S-boxes
            j = 0
            Bn = [0] * 32
            pos = 0
            while j < 8:
                # Gaseste coordonatele in Tabelele de permutare pt. B-uri
                m = (B[j][0] << 1) + B[j][5] # primul si ultimul bit
                n = (B[j][1] << 3) + (B[j][2] << 2) + (B[j][3] << 1) + B[j][4] # bitii din mijloc

                # Gaseste valoarea de permutat
                v = des._sbox[j][(m << 4) + n]

                # Transforma valoarea in biti si pune-o la rezultat Bn
                Bn[pos] = (v & 8) >> 3
                Bn[pos + 1] = (v & 4) >> 2
                Bn[pos + 2] = (v & 2) >> 1
                Bn[pos + 3] = v & 1

                pos += 4
                j += 1

            # Permuta concatenarea de la B[1] pana la B[8] (Bn)
            self.R = self.permutare(des._p, Bn)

            # Xor cu L[i - 1]
            self.R = list(map(lambda x, y: x ^ y, self.R, self.L))

            # L[i] devine R[i - 1]
            self.L = tempR

            i += 1
            iteration += iteration_adjustment

        # Permutare Finala : L[16]R[16] perm. fp
        print("AAAAAA:")
        self.final = self.permutare(des._fp, self.R + self.L)
        return self.final

    # spargem in blocuri de cate 8 biti si ii dam la des_crypt()
    def crypt(self, data):

        # Error check the data
        if not data:
            return ''
        if len(data) % self.block_size != 0:
            if not self.getPadding():
                raise ValueError("Invalid data length, data must be a multiple of " + str(
                    self.block_size) + " bytes\n. Try setting the optional padding character")
            else:
                # Bagam caracterul nostru ca padding
                data += (self.block_size - (len(data) % self.block_size)) * self.getPadding().decode("ascii")

        print("Len of data: %f" % (len(data) / self.block_size))

        i = 0
        dict = {}
        result = []
        # cached = 0
        # lines = 0
        while i < len(data):
            # Test code for caching encryption results

            block = self.String_to_BitList2(data[i:i + 8])  ############# !!!!!!! mesaj , 2
            print("DATA BLOCK:")
            print(block)  ### CORECT ########################

            processed_block = self.des_crypt(block)
            print("ALELUIA")
            print(processed_block)
            # Add the resulting crypted block to our list

            result.append(self.BitList_to_String(processed_block))
            print("REZ")
            print(result)

            i += 8  # 8 by 8 for each possible word in the message

        return bytes.fromhex('').join(result)

    def encrypt(self, data, pad=None, padmode=None):
        data = self._checkIfUnicode(data)
        if pad is not None:
            pad = self._checkIfUnicode(pad)
        data = self._padData(data, pad, padmode)
        return self.crypt(data)


if __name__ == "__main__":
    print("DES")
    mesaj = input("Mesaj: ")
    # cheie = input("Cheie: ")

    # mesaj = "piulita12"
    cheie = "cheie222"

    # Cheia trebuie sa fie de cel putin 8 caractere

    # DACA MESAJUL ESTE PREA SCURT , IN LOCUL UNDE AR VENII CARACTERE SUNT PUSE X-uri sau alt char care il dam
    DES = des(cheie, "X", PAD_NORMAL)
    result = DES.crypt(mesaj)
    print("Mesaj: " + mesaj)
    print(result.hex())
