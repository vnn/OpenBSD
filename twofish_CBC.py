#!/usr/bin/env python3.4

"""
Encrypt or decrypt a file using Twofish cipher and mode CBC.
"""

__version__ = '0.1'

import argparse
from getpass import getpass
import os

from twofish import Twofish


class TwofishCipherCBC:

    """ This class handles all the cryptographic operations. """

    def __init__(self, key, iv=None):
        self.__bs = bs
        self.__iv = iv if iv else os.urandom(self.__bs)
        self.__prev = self.__iv  # To be used with XOR in CBC Mode
        self.__cipher = Twofish(key)

    def encrypt(self, buffer, first_buffer=False):
        """
        Return an encrypted buffer.
        """
        if len(buffer) != bs:
            self.__prev = self.__cipher.encrypt(self.__xor(self.__add_pad(buffer)))
            return self.__prev
        else:
            self.__prev = self.__cipher.encrypt(self.__xor(buffer))
            if first_buffer:
                return self.__iv + self.__prev
            else:
                return self.__prev

    def decrypt(self, buffer, unpad=False):
        """
        Return a decrypted buffer.
        """
        if unpad:
            return self.__del_pad(self.__xor(self.__cipher.decrypt(buffer)))
        else:
            self.__prev = self.__xor(self.__cipher.decrypt(buffer))
            return self.__prev

    def __add_pad(self, buffer):
        """
        Return a buffer with padding added (ISO 10126).
        """
        padding = self.__bs - len(buffer)
        for idx, i in enumerate(range(padding), start=1):
            buffer += os.urandom(1) if idx != padding else bytes([padding])
        return buffer

    def __del_pad(self, buffer):
        """
        Return a buffer with padding removed (ISO 10126).
        """
        return buffer[:-buffer[-1]]

    def __xor(self, buffer):
        """
        XOR a buffer with the previous encrypted buffer,
        or with the initializing vector (for the 1st buffer only).
        """
        buffer = int.from_bytes(buffer, byteorder='big')
        prev_buffer = int.from_bytes(self.__prev, byteorder='big')
        return (buffer ^ prev_buffer).to_bytes(self.__bs, byteorder='big')


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
        bs = 16

        # Get the initialization vector from the first 16 bytes
        # of the file and use it with the key to initialize
        # Twofish cipher.
        if args.decrypt:
            iv = f.read(bs)
            cipher = TwofishCipherCBC(get_key(), iv)
        # Initialize Twofish cipher with the key and write the iv
        # + the first encrypted block to the outfile.
        elif args.encrypt:
            buffer = f.read(bs)
            cipher = TwofishCipherCBC(get_key())
            outfile.write(cipher.encrypt(buffer, first_buffer=True))

        # Process the rest of the file chunk by chunk.
        # When decrypting, wait for the last block, then remove
        # previously added padding.
        while True:
            buffer = f.read(bs)
            if buffer and args.encrypt:
                outfile.write(cipher.encrypt(buffer))
            elif buffer and args.decrypt:
                if f.tell() == filesize:
                    outfile.write(cipher.decrypt(buffer, unpad=True))
                else:
                    outfile.write(cipher.decrypt(buffer))
            else:
                print('done')
                break
