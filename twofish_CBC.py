#!/usr/bin/env python3.4

"""
Encrypt or decrypt a file using Twofish cipher
and cipher block chaining mode (CBC).

https://www.schneier.com/twofish.html
https://pypi.python.org/pypi/twofish/
http://csrc.nist.gov/publications/fips/fips81/fips81.htm

About:
=======
Twofish cipher is initialized with a user defined password.
It operates exclusively on 16 bytes blocks. The main function
reads a file chunk by chunk and writes the data processed
via the TwofishCipher class to the outfile.

CBC Encryption:
===========
First, we generate an initialization vector (16 bytes
generated via OpenBSD urandom), XOR it with the first clear
block to start the chain and encrypt the result. The iv
is prepended to this first encrypted block and written to
the outfile.

For other blocks, XOR each clear block with the previous
encrypted block, then encrypt the result and write it to
the outfile.

Same thing apply for the last block except we add some extra
padding to obtain a 16 bytes block to work with the cipher.
If this last block is already equal to 16 bytes, we'll
add an extra block of 16 bytes full of padding to keep
compatibility with decryption.

CBC Decryption:
===========
First read the first block of the file: this is the iv we used
during encryption process.

We reverse the operations we did previously, so decrypt each block
and XOR it with the previously encrypted block to get the clear
result.

Same thing apply for the latest block except we remove the extra
padding.
"""

__version__ = '0.1'

import argparse
from getpass import getpass
import os

from twofish import Twofish

class TwofishCipher:

    """
    This class handles all the cryptographic operations.
    """

    def __init__(self, key, file_size):
        self.__cipher = Twofish(key)
        self.__prev = bytes()
        self.__file_size = file_size
        self.__block_count = 0

    def encrypt(self, buf):
        """ Return an encrypted block. """
        self.__block_count += block_size
        # First block, iv generated and prepened to the 1st encrypted block.
        if not self.__prev:
            iv = os.urandom(block_size)
            self.__prev = self.__cipher.encrypt(self.__xor(buf, iv))
            return iv + self.__prev
        # Default blocks.
        elif (len(buf) == block_size) and (self.__block_count != self.__file_size):
            self.__prev = self.__cipher.encrypt(self.__xor(buf, self.__prev))
            return self.__prev
        # Last block, add some extra padding.
        elif len(buf) != block_size:
            self.__prev = self.__cipher.encrypt(self.__xor(self.__pad(buf), self.__prev))
            return self.__prev
        # Last block equal to 16 bytes, add an extra 16 bytes padding block.
        elif self.__block_count == self.__file_size:
            random_block = os.urandom(block_size - 1) + bytes([16])
            self.__prev = self.__xor(self.__cipher.decrypt(buf), self.__prev)
            return self.__prev + random_block

    def decrypt(self, buf):
        """ Return a decrypted block. """
        self.__block_count += block_size
        # First block of the file: this is the initialization vector.
        # Return an empty byte string to maintain compatibility with write().
        if not self.__prev:
            self.__prev = buf
            return b''
        # Decrypt a block.
        elif self.__block_count != self.__file_size:
            xored = self.__xor(self.__cipher.decrypt(buf), self.__prev)
            self.__prev = buf
            return xored
        # Decrypt the last block and remove its padding.
        else:
            return self.__unpad(self.__xor(self.__cipher.decrypt(buf), self.__prev))

    def __pad(self, buf):
        """ Return a block with padding added (ISO 10126). """
        padding = block_size - len(buf)
        for idx, i in enumerate(range(padding), start=1):
            buf += os.urandom(1) if idx != padding else bytes([padding])
        return buf

    def __unpad(self, buf):
        """ Return a block with padding removed (ISO 10126). """
        return buf[:-buf[-1]] if buf[:-buf[-1]] else b''

    def __xor(self, x, y):
        """ Return the XOR from two 16bytes blocks. """
        x = int.from_bytes(x, byteorder='big')
        y = int.from_bytes(y, byteorder='big')
        return (x ^ y).to_bytes(16, byteorder='big')


def get_key():
    """ Return a key grabbed from used input. """
    if args.encrypt:
        prompt = lambda: (getpass('Password: '),
                          getpass('Retype password: '))
        key, key_verif = prompt()
        while key != key_verif:
            print('Passwords do not match. Try again')
            key, key_verif = prompt()
    elif args.decrypt:
        key = getpass()
    return key.encode()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='twofishcrypt', description='Encrypt or decrypt file using Twofish')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', const=True, action='store_const',
                       help='encrypt file')
    group.add_argument('-d', '--decrypt', const=True, action='store_const',
                       help='decrypt file')
    parser.add_argument('infile', type=argparse.FileType('rb'),
                        metavar='<infile>', help='read data from <infile>')
    parser.add_argument('outfile', type=argparse.FileType('wb'),
                         metavar='<outfile>',
                         help='write data to <outfile>')
    args = parser.parse_args()

    with open(args.infile.name, 'rb') as f:
        file_size = os.path.getsize(args.infile.name)
        outfile = open(args.outfile.name, 'wb')
        block_size = 16

        cipher = TwofishCipher(get_key(), file_size)

        # Process the file chunk by chunk.
        while True:
            buf = f.read(block_size)

            if buf and args.encrypt:
                outfile.write(cipher.encrypt(buf))
            elif buf and args.decrypt:
                outfile.write(cipher.decrypt(buf))
            else:
                print('done')
                break
