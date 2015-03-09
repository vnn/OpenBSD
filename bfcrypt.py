#!/usr/bin/env python3.4

"""
Encrypt or decrypt a small file using Blowfish cipher.
"""

import argparse
from getpass import getpass
import os
import sys

from Crypto.Cipher import Blowfish


class BlowfishCipher:

    """ This class handles all the cryptograpgic operations. """

    def __init__(self, password):
        self.__cipher = Blowfish.new(password)

    def encrypt(self, infile):

        """ Encrypt file and add necessary padding bytes. """

        # The padding boundary is specified by the latest byte.
        # See: scheme ISO 10126
        padding = 8 - (len(infile) % 8)
        for idx, i in enumerate(range(padding), start=1):
            infile += os.urandom(1) if idx != padding else str(padding).encode()
        encrypted_file = self.__cipher.encrypt(infile)

        return encrypted_file

    def decrypt(self, infile):

        """ Decrypt file and remove padding bytes. """

        original_file = self.__cipher.decrypt(infile)
        padding = int(original_file.decode()[-1])

        return original_file[:-padding]


def get_password():

    """ This function handles password related operations. """

    if args.encrypt:
        prompt = lambda: (getpass('Password: '), getpass('Retype password: '))
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
    parser.add_argument('outfile', type=argparse.FileType('wb'), nargs='?',
                         metavar='<outfile>', default=sys.stdout,
                         help='write data to <outfile> (default: stdout)')
    args = parser.parse_args()

    # Init cipher with password read from user input, then read infile.
    bfcrypt = BlowfishCipher(get_password())
    infile = args.infile.read()

    # Process cryptographic operations and store results.
    data = bfcrypt.encrypt(infile) if args.encrypt else bfcrypt.decrypt(infile)

    # Write processed data to stdout or outfile.
    data = data.decode() if args.outfile.name == '<stdout>' else data
    args.outfile.write(data)
