#!/usr/bin/env python3.4

"""
Encrypt or decrypt a file using Blowfish cipher.
"""

import argparse
from getpass import getpass
import os
import sys

from Crypto.Cipher import Blowfish


class BlowfishCore:

    """ This class handles all the cryptograpgic operations. """

    def __init__(self, password):
        self.__cipher = Blowfish.new(password)

    def encrypt(self, infile):

        """ Encrypt file and add necessary padding bytes. """

        padding = 8 - (len(infile) % 8)
        for i in range(padding-1):
            infile += os.urandom(1)
        # The latest byte is used as an indicator.
        infile += bytes(str(padding), 'utf-8')
        encrypted_file = self.__cipher.encrypt(infile)

        return encrypted_file

    def decrypt(self, infile):

        """ Decrypt file and remove padding bytes. """

        original_file = self.__cipher.decrypt(infile)
        padding = int(str(original_file)[-2])

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
                       help='Encrypt file.')
    group.add_argument('-d', '--decrypt', const=True, action='store_const',
                       help='Decrypt file.')
    parser.add_argument('infile', type=argparse.FileType('r'),
                        metavar='<infile>', help='Read data from <infile>.')
    parser.add_argument('outfile', type=argparse.FileType('w'), nargs='?',
                         metavar='<outfile>', default=sys.stdout,
                         help='Write data to <outfile>.')
    args = parser.parse_args()

    # Init cipher with password read from user input, then read infile.
    bfcrypt = BlowfishCore(get_password())
    with open(args.infile.name, 'rb') as f:
        infile = f.read()

    # Process cryptographic operations and store results.
    data = bfcrypt.encrypt(infile) if args.encrypt else bfcrypt.decrypt(infile)

    # Write processed data to stdout or outfile.
    if args.outfile.name == '<stdout>':
        sys.stdout.write(str(data)+'\n')
    else:
        with open(args.outfile.name, 'wb') as f:
            f.write(data)
