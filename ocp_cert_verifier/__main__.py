from argparse import ArgumentParser
import sys

from openshift.dynamic.exceptions import ForbiddenError

from . import verify


def main(args=None):
    args = args or sys.argv[1:]
    parser = ArgumentParser(description='Verify expiration of certificates in OCP secrets')
    parser.add_argument('namespace',
                        help='OCP namesapce, aka project, to verify')
    parser.add_argument('--grace-period', type=int, default=30,
                        help='Warn if certificate expires in less than grace period, in days')
    args = parser.parse_args(args)
    try:
        verify(args.namespace, args.grace_period)
    except ForbiddenError:
        print('ERROR: Unable to access project {}'.format(args.namespace))


if __name__ == '__main__':
    main()
