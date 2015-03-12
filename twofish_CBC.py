#!/usr/bin/env python3.4

"""
Encrypt or decrypt a file using Twofish cipher
and cipher block chaining mode (CBC).
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

    def __init__(self, key):
        self.__cipher = Twofish(key)
        self.__block_size = block_size
        self.__prev = bytes()

    def encrypt(self, buf, extra_block=False):
        """ Return an encrypted block. """
        if len(buf) == block_size and not extra_block:
            # Generate an initialization vector, XOR it with the first
            # clear block to start the chain and encrypt the result.
            if not self.__prev:
                iv = os.urandom(self.__block_size)
                self.__prev = iv
                self.__prev = self.__cipher.encrypt(self.__xor(buf, self.__prev))
                return iv + self.__prev
            # Encrypt a block.
            else:
                self.__prev = self.__cipher.encrypt(self.__xor(buf, self.__prev))
                return self.__prev
        else:
            if len(buf) != self.__block_size:
                self.__prev = self.__cipher.encrypt(self.__xor(self.__pad(buf), self.__prev))
                return self.__prev
            else:
                random_block = os.urandom(self.__block_size - 1) + bytes([16])
                self.__prev = self.__xor(self.__cipher.decrypt(buf), self.__prev)
                return self.__prev + random_block

    def decrypt(self, buf, unpad=False):
        """ Return a decrypted block. """
        # First block of the file: this is the initialization vector.
        # Store it into self.__prev for later use with the 1st encrypted block.
        # Return an empty byte string to keep compatibility with write().
        if not self.__prev:
            self.__prev = buf
            return b''
        # Decrypt a block.
        elif not unpad:
            xored = self.__xor(self.__cipher.decrypt(buf), self.__prev)
            self.__prev = buf
            return xored
        # Decrypt the last block and remove its padding.
        else:
            return self.__unpad(self.__xor(self.__cipher.decrypt(buf), self.__prev))

    def __pad(self, buf):
        """ Return a block with padding added (ISO 10126). """
        padding = self.__block_size - len(buf)
        for idx, i in enumerate(range(padding), start=1):
            buf += os.urandom(1) if idx != padding else bytes([padding])
        return buf

    def __unpad(self, buf):
        """ Return a buf with padding removed (ISO 10126). """
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
        filesize = os.path.getsize(args.infile.name)
        outfile = open(args.outfile.name, 'wb')
        block_size = 16

        # Initialize Twofish cipher with the key provided
        # by the user.
        cipher = TwofishCipher(get_key())

        # Process the rest of the file chunk by chunk.
        # When decrypting, wait for the last block, then remove
        # previously added padding.
        while True:
            buf = f.read(block_size)

            if buf and args.encrypt:
                if f.tell() == filesize and len(buf) == block_size:
                    outfile.write(cipher.encrypt(buf, extra_block=True))
                else:
                    outfile.write(cipher.encrypt(buf))
            elif buf and args.decrypt:
                if f.tell() == filesize:
                    outfile.write(cipher.decrypt(buf, unpad=True))
                else:
                    outfile.write(cipher.decrypt(buf))
            else:
                print('done')
                break
