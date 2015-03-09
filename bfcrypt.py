#!/usr/bin/env python3.4

"""
Encrypt and decrypt a file using Blowfish.
"""

import argparse
import os
from Crypto.Cipher import Blowfish
from getpass import getpass


class BlowfishCore:

    """ This class handles all the cryptograpgic operations. """

    def __init__(self, password):
        self.cipher = Blowfish.new(password)

    def encrypt(self, original_file):

        """ Encrypt a file using Blowfish. """

        # Calculate padding and add it to the file.
        # The latest byte is equel to the total of padding bytes.
        padding_length = 8 - (len(original_file) % 8)
        for i in range(padding_length-1):
            original_file += os.urandom(1)
        original_file += bytes(str(padding_length), 'utf-8')

        encrypted_file = self.cipher.encrypt(original_file)
        return encrypted_file

    def decrypt(self, encrypted_file):

        """ Decrypt a file using Blowfish. """

        original_file = self.cipher.decrypt(encrypted_file)
        padding = int(str(original_file)[-2])
        return original_file[:-padding]


def get_password():

    """ This function handles password related operations. """

    if args.encrypt:
        pprompt = lambda: (
        getpass('Password: '), getpass('Retype password: '))
        password, password_verif = pprompt()
        while password != password_verif:
            print('Passwords do not match. Try again')
            password, password_verif = pprompt()
    elif args.decrypt:
        password = getpass()
    return password


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='bfcrypt',
        description='Encrypt or decrypt file using Blowfish')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', const=True, action='store_const',
                       help='Encrypt file.')
    group.add_argument('-d', '--decrypt', const=True, action='store_const',
                       help='Decrypt file.')
    parser.add_argument('infile', type=argparse.FileType('r'),
                       metavar='<infile>', help='Read data from <infile>.')
    parser.add_argument('outfile', type=argparse.FileType('w'), nargs='?',
                        metavar='<outfile>', help='Write data to <outfile>.')
    args = parser.parse_args()

    # Get password from user input, open the file
    # to be processed and initialize Blowfish cypher.
    password = get_password()
    with open(args.infile.name, 'rb') as f:
        in_data = f.read()
    bfcore = BlowfishCore(password)

    # Process cryptographic operations.
    if args.encrypt:
        out_data = bfcore.encrypt(in_data)
    elif args.decrypt:
        out_data = bfcore.decrypt(in_data)

    # Write processed data to file or stdin.
    if args.outfile:
        with open(args.outfile.name, 'wb') as f:
            f.write(out_data)
    else:
        print(out_data)
