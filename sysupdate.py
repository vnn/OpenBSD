#!/usr/bin/env python

"""
Manage OpenBSD-stable userland, ports and kernel updates.
"""

__version__ = '0.1'

import os
import subprocess
import argparse


def cmd(cmd):
    subprocess.call(cmd, shell=True)


def fetch():

    """ Fetch corresponding sources from CVS. """

    print('Fetching OpenBSD '+repo+' tree from CVS...')
    cmd('cd /usr && cvs -qd '+cvs_root+' get -r'+release+' -P '+repo)


def update():

    """ Update corresponding sources from CVS. """

    print('Updating OpenBSD '+repo+' tree from CVS...')
    cmd('cd /usr/'+repo+' && cvs -d '+cvs_root+' -q up -r'+release + ' -Pd')


def build():

    """ Build and install corresponding part of the system. """

    print('Rebuilding '+repo+'...')
    if args.build == 'kernel':
        cmd('cd /usr/src/sys/arch/'+arch+'/conf && config GENERIC.MP')
        cmd('cd /usr/src/sys/arch/'+arch+'/compile/GENERIC.MP '
            '&& make clean && make && make install')
    elif args.build == 'userland':
        cmd('rm -rf /usr/obj/* && cd /usr/src && make obj')
        cmd('cd /usr/src/etc && env DESTDIR=/ make distrib-dirs')
        cmd('cd /usr/src && make build')
    elif args.build == 'xenocara':
        cmd('rm -rf /usr/xobj/*')
        cmd('cd /usr/xenocara && make bootstrap && make obj && make build')


if __name__ == "__main__":
    # Parse arguments.
    parser = argparse.ArgumentParser(
        description=('Manage OpenBSD-stable userland, '
                     'ports and kernel updates.'), prog='sysupdate')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--fetch',
                       choices=['ports', 'src', 'xenocara'],
                       help='Fetch sources from CVS.')
    group.add_argument('-u', '--update',
                       choices=['ports', 'src', 'xenocara'],
                       help='Update source tree from CVS.')
    group.add_argument('-b', '--build',
                       choices=['kernel', 'userland', 'xenocara'],
                       help='Rebuild and install a part of the system.')
    parser.add_argument('-c', '--cvs',
                        nargs=1, metavar='CVSROOT',
                        help='Define CVS root server.')
    args = parser.parse_args()

    # Check permissions.
    if os.getenv('USER') != 'root':
        print('Error: this command should be run as root')
        exit()

    # Define configuration variables.
    default_cvs_root = 'anoncvs@anoncvs.fr.openbsd.org:/cvs'
    cvs_root = args.cvs if args.cvs else default_cvs_root
    release = 'OPENBSD_' + os.uname()[2].replace('.', '_')
    repo = [vars(args)[i] for i in vars(args) if vars(args)[i] and i != 'cvs'][0]
    arch = os.uname()[4]

    # Process arguments.
    if args.fetch:
        fetch()
    elif args.update:
        update()
    elif args.build:
        build()
    print('done')
