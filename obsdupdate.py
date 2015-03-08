#!/usr/bin/env python3.4

"""
Manage OpenBSD userland, ports and kernel updates.

Usage:
  obsdupdate --fetch  (ports | src | xenocara) [(--cvs <cvsroot>)]
  obsdupdate --update (ports | src | xenocara) [(--cvs <cvsroot>)]
  obsdupdate --build  (kernel | userland | xenocara) [(--cvs <cvsroot>)]
  obsdupdate --help
  obsdupdate --version

Options:
  -h --help        Show this screen.
  -v --version     Show version.
  -f --fetch       Fetch sources onto the system.
  -u --update      Update source tree.
  -b --build       Rebuild the system.
  -c --cvs         Define anonymous CVS root server.
"""


import os
import sys
import subprocess
import docopt


def main():

    """
    Fetch, update or build specified part of the system.
    """

    def cmd(cmd):
        subprocess.call(cmd, shell=True)

    default_cvs = 'anoncvs@anoncvs.fr.openbsd.org:/cvs'
    cvsroot = args['--cvs'] if args['--cvs'] else default_cvs
    release = 'OPENBSD_' + os.uname()[2].replace('.', '_')
    arch = os.uname()[4]
    part = sys.argv[2]

    # Fetch
    if args['--fetch']:
        print('Fetching OpenBSD '+part+' tree from CVS...')
        cmd('cd /usr && cvs -qd '+cvsroot+' get -r'+release+' -P '+part)
    # Update
    elif args['--update']:
        print('Updating OpenBSD '+part+' tree from CVS...')
        cmd('cd /usr/'+part+' && cvs -d '+cvsroot+' -q up -r'+release + ' -Pd')
    # Build
    elif args['--build']:
        print('Rebuilding '+part+'...')
        if args['kernel']:
            cmd('cd /usr/src/sys/arch/'+arch+'/conf && config GENERIC.MP')
            cmd('cd /usr/src/sys/arch/'+arch+'/compile/GENERIC.MP '
                '&& make clean && make && make install')
        elif args['userland']:
            cmd('rm -rf /usr/obj/* && cd /usr/src && make obj')
            cmd('cd /usr/src/etc && env DESTDIR=/ make distrib-dirs')
            cmd('cd /usr/src && make build')
        elif args['xenocara']:
            cmd('rm -rf /usr/xobj/*')
            cmd('cd /usr/xenocara && make bootstrap && make obj && make build')

    print('done')


if __name__ == "__main__":
    args = docopt.docopt(__doc__, version='obsdupdate 0.2.0')
    main()
