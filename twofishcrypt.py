#!/usr/bin/env python3.4

"""
Encrypt or decrypt a file using Twofish cipher
designed by Bruce Schneier.
"""

__version__ = '0.1'

import argparse
from getpass import getpass
import os

from twofish import Twofish


class TwofishCipher:

    """ This class handles all the cryptographic operations. """

    def __init__(self, key):
        self.__bs = bs
        self.__cipher = Twofish(key)

    def __add_pad(self, chunk):
        """ Return a chunk with padding added (ISO 10126). """
        padding = self.__bs - len(chunk)
        for idx, i in enumerate(range(padding), start=1):
            chunk += os.urandom(1) if idx != padding else bytes([padding])
        return chunk

    def __del_pad(self, chunk):
        """ Return a chunk with padding removed (ISO 10126). """
        return chunk[:-chunk[-1]]

    def encrypt(self, chunk):
        """ Return an encrypted chunk. """
        if len(chunk) != bs:
            return self.__cipher.encrypt(self.__add_pad(chunk))
        else:
            return self.__cipher.encrypt(chunk)

    def decrypt(self, chunk, unpad=False):
        """ Return a decrypted chunk. """
        if unpad:
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
        outfile = open(args.outfile.name, 'wb')
        bs = 16
        filesize = os.path.getsize(args.infile.name)
        # Initialize twofish cipher with key.
        cipher = TwofishCipher(get_key())

        # Process the rest of the file chunk by chunk.
        while True:
            chunk = f.read(bs)
            if chunk and args.encrypt:
                outfile.write(cipher.encrypt(chunk))
            elif chunk and args.decrypt:
                if f.tell() == filesize:
                    outfile.write(cipher.decrypt(chunk, True))
                else:
                    outfile.write(cipher.decrypt(chunk))
            else:
                print('done')
                break
