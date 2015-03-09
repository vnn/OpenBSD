#!/usr/bin/env python3.4

"""
Encrypt and decrypt a file using Blowfish cipher.
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

        """ Encrypt a file using Blowfish. """

        # Calculate padding and add it to the file.
        padding = 8 - (len(infile) % 8)
        for i in range(padding-1):
            infile += os.urandom(1)
        # The latest byte is equal to the total of padding bytes.
        infile += bytes(str(padding), 'utf-8')

        encrypted_file = self.__cipher.encrypt(infile)
        return encrypted_file

    def decrypt(self, infile):

        """ Decrypt a file using Blowfish. """

        original_file = self.__cipher.decrypt(infile)
        # Remove the padding added during encryption.
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
    parser.add_argument('infile', type=argparse.FileType('r'), metavar='<infile>',
                        help='Read data from <infile>.')
    parser.add_argument('outfile', type=argparse.FileType('w'),
                         default=sys.stdout, metavar='<outfile>', nargs='?',
                         help='Write data to <outfile>.')
    args = parser.parse_args()

    # Get password from user input, get data from stdin
    # or file, and initialize Blowfish cipher.
    password = get_password()
    with open(args.infile.name, 'rb') as f:
        in_data = f.read()
    bfcrypt = BlowfishCore(password)

    # Process cryptographic operations.
    if args.encrypt:
        out_data = bfcrypt.encrypt(in_data)
    elif args.decrypt:
        out_data = bfcrypt.decrypt(in_data)

    # Write processed data to file or stdin.
    if args.outfile.name == '<stdout>':
        sys.stdout.write(str(out_data)+'\n')
    else:
        with open(args.outfile.name, 'wb') as f:
            f.write(out_data)
