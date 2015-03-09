#!/usr/bin/env python3.4

"""
Encrypt or decrypt a file using Blowfish cipher.
"""

import argparse
from getpass import getpass
import os

from Crypto.Cipher import Blowfish
from Crypto import Random


class BlowfishCipher:

    """ This class handles all the cryptograpgic operations. """

    def __init__(self, key, iv=None):
        self.__bs = bs
        self.__iv = iv if iv else Random.new().read(self.__bs)
        self.__cipher = Blowfish.new(key, Blowfish.MODE_CBC, self.__iv)

    def __add_pad(self, chunk):
        """ Return a chunk with padding added (ISO 10126). """
        padding = self.__bs - (len(chunk) % self.__bs)
        for idx, i in enumerate(range(padding), start=1):
            chunk += os.urandom(1) if idx != padding else str(padding).encode()
        return chunk

    def __del_pad(self, chunk):
        """ Return a chunk with padding removed (ISO 10126). """
        return chunk[:-int(chunk[-1:])]

    def encrypt(self, chunk, first_part=False):
        """ Return an encrypted chunk. """
        # Prepend iv to the first chunk.
        if first_part and (len(chunk) != chunk_size):
            return self.__iv + self.__cipher.encrypt(self.__add_pad(chunk))
        elif first_part:
            return self.__iv + self.__cipher.encrypt(chunk)
        elif len(chunk) != chunk_size:
            return self.__cipher.encrypt(self.__add_pad(chunk))
        else:
            return self.__cipher.encrypt(chunk)

    def decrypt(self, chunk):
        """ Return a decrypted chunk. """
        if len(chunk) != chunk_size:
            return self.__del_pad(self.__cipher.decrypt(chunk))
        else:
            return self.__cipher.decrypt(chunk)


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

    return key


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='bfcrypt', description='Encrypt or decrypt file using Blowfish')
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
        outfile = open(args.outfile.name, 'wb')
        bs = Blowfish.block_size
        chunk_size = 720

        # Init cipher for encryption using key from user input and iv.
        if args.decrypt:
            iv = f.read(bs)
            bfcrypt = BlowfishCipher(get_key(), iv)

        # Init cipher for decryption using key from user input,
        # and prepend iv to the first encrypted chunk.
        elif args.encrypt:
            chunk = f.read(chunk_size)
            bfcrypt = BlowfishCipher(get_key())
            outfile.write(bfcrypt.encrypt(chunk, first_part=True))

        # Encrypt or decrypt the rest of the file chunk by chunk.
        while True:
            chunk = f.read(chunk_size)
            if chunk and args.encrypt:
                outfile.write(bfcrypt.encrypt(chunk))
            elif chunk and args.decrypt:
                outfile.write(bfcrypt.decrypt(chunk))
            else:
                print('done')
                break
