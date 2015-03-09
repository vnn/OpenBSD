#!/usr/bin/env python3.4

"""
Encrypt or decrypt a file using Blowfish cipher.
"""

import argparse
from getpass import getpass
import os
import sys

from Crypto.Cipher import Blowfish
from Crypto import Random


class BlowfishCipher:

    """ This class handles all the cryptograpgic operations. """

    def __init__(self, password, iv=None):
        self.__bs = bs
        self.__iv = iv if iv else Random.new().read(self.__bs)
        self.__cipher = Blowfish.new(password, Blowfish.MODE_CBC, self.__iv)

    def __add_pad(self, chunk):
        """ Add padding bytes. """
        # The padding boundary is specified by the latest byte.
        # See: scheme ISO 10126
        padding = self.__bs - (len(chunk) % self.__bs)
        for idx, i in enumerate(range(padding), start=1):
            chunk += os.urandom(1) if idx != padding else str(padding).encode()
        return chunk

    def __del_pad(self, chunk):
        """ Remove padding bytes. """
        return chunk[:-int(chunk[-1:])]

    def encrypt(self, chunk, first_part=False):
        """ Encrypt chunk. """
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
        """ Decrypt chunk. """
        if len(chunk) != chunk_size:
            return self.__del_pad(self.__cipher.decrypt(chunk))
        else:
            return self.__cipher.decrypt(chunk)


def get_password():
    """ This function handles password related operations. """
    if args.encrypt:
        prompt = lambda: (getpass('Password: '),
                          getpass('Retype password: '))
        password, password_verif = prompt()
        while password != password_verif:
            print('Passwords do not match. Try again')
            password, password_verif = prompt()
    elif args.decrypt:
        password = getpass()

    return password


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
                         help='write data to <outfile> (default: stdout)')
    args = parser.parse_args()

    with open(args.infile.name, 'rb') as f:
        with open(args.outfile.name, 'wb') as fp:
            bs = Blowfish.block_size
            chunk_size = 720

            # Init the cipher using password from user input and iv.
            if args.decrypt:
                iv = f.read(bs)
                bfcrypt = BlowfishCipher(get_password(), iv)
            # Init the cipher using password from user input,
            # and prepend iv to the first encrypted chunk.
            elif args.encrypt:
                chunk = f.read(chunk_size)
                bfcrypt = BlowfishCipher(get_password())
                fp.write(bfcrypt.encrypt(chunk, first_part=True))

            # Encrypt or decrypt the file chunk by chunk.
            while True:
                chunk = f.read(chunk_size)
                if chunk and args.encrypt:
                    fp.write(bfcrypt.encrypt(chunk))
                elif chunk and args.decrypt:
                    fp.write(bfcrypt.decrypt(chunk))
                else:
                    break

    print('done')
