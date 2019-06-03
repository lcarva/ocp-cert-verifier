#!/bin/env python3

from argparse import ArgumentParser
from base64 import b64decode
from collections import namedtuple
from datetime import datetime, timedelta

from kubernetes import config
from openshift.dynamic import DynamicClient
from openshift.dynamic.exceptions import ForbiddenError
from OpenSSL import crypto


CERT_START_TOKEN = '-----BEGIN CERTIFICATE-----'
CERT_END_TOKEN = '-----END CERTIFICATE-----'


Certificate = namedtuple('Certificate', 'name,expires_soon,expiration,expiration_relative')


def check(namespace, grace_period):
    secrets = get_ocp_secrets(namespace)

    for secret_name, key, value in list_certs(secrets):
        cert = process_cert_text(f'{namespace}:{secret_name}:{key}', value, grace_period)

        level = 'OK'
        if cert.expires_soon:
            level = 'WARNING'

        print('%s: %s expires in %s days on: %s' %
              (level, cert.name, cert.expiration_relative.days, cert.expiration))


def get_ocp_secrets(namespace):
    k8s_client = config.new_client_from_config()
    dyn_client = DynamicClient(k8s_client)
    v1_secrets = dyn_client.resources.get(api_version='v1', kind='Secret')
    return v1_secrets.get(namespace=namespace).items


def list_certs(secrets):
    for secret in secrets:
        # Certificates are only stored in "Opaque" secrets
        if secret['type'] != 'Opaque':
            continue
        secret_name = secret['metadata']['name']
        for key, encoded_text in secret['data'].items():
            try:
                text = b64decode(encoded_text).decode('utf-8')
            except UnicodeDecodeError:
                # Not a text file, ignore it.
                continue
            if CERT_START_TOKEN not in text or CERT_END_TOKEN not in text:
                continue
            # The cert file could contain multiple certs. Let's split them up.
            for cert in split_certs(text):
                yield secret_name, key, cert


def split_certs(text):
    context = []
    for line in text.splitlines():
        if CERT_END_TOKEN == line:
            context.append(line)
            yield '\n'.join(context)
            continue

        if CERT_START_TOKEN == line:
            context = []
        context.append(line)


def process_cert_text(name, text, grace_period):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, text)
    expiration = datetime.strptime(cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
    now = datetime.utcnow()
    expires_in = expiration - now
    expires_soon = expires_in < timedelta(days=grace_period)
    return Certificate(name, expires_soon, expiration, expires_in)


if __name__ == '__main__':
    parser = ArgumentParser(description='Check expiration of certificates in OCP secrets')
    parser.add_argument('namespace',
                        help='OCP namesapce, aka project, to check')
    parser.add_argument('--grace-period', type=int, default=30,
                        help='Warn if certificate expires in less than grace period, in days')
    args = parser.parse_args()
    try:
        check(args.namespace, args.grace_period)
    except ForbiddenError:
        print('ERROR: Unable to access project {}'.format(args.namespace))
