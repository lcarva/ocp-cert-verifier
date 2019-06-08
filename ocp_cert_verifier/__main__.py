from argparse import ArgumentParser
import sys

from openshift.dynamic.exceptions import ForbiddenError

from . import verify
from .utils import setup_app_logger


LOGGER = setup_app_logger()


def main(args=None):
    args = args or sys.argv[1:]
    parser = ArgumentParser(description='Verify expiration of certificates in OCP secrets')
    parser.add_argument('namespace',
                        help='OCP namesapce, aka project, to verify')
    parser.add_argument('--grace-period', type=int, default=30,
                        help='Warn if certificate expires in less than grace period, in days')

    parser.add_argument('--in-cluster', action='store_true', default=False,
                        help='Running in a pod in an OCP cluster?')

    parser.add_argument('--email-to',
                        help='Send email notification on warnings to given address')
    parser.add_argument('--smtp-server',
                        help='The SMTP server to be used for email notifications')
    parser.add_argument('--email-from',
                        help='Email sender address')

    args = parser.parse_args(args)
    smtp_info = {
        'server': args.smtp_server,
        'to': args.email_to,
        'from': args.email_from,
    }
    try:
        verify(args.namespace, args.grace_period, args.in_cluster, smtp_info)
    except ForbiddenError:
        LOGGER.error('Unable to access project %s', args.namespace)


if __name__ == '__main__':
    main()
