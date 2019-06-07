from pytest import fixture

from OpenSSL import crypto


@fixture(scope='session')
def generate_cert():
    """"Return a function that generates certificates."""

    def make_cert(cn, not_after):
        # Create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)

        # Create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "Massachusetts"
        cert.get_subject().L = "Haverhill"
        cert.get_subject().OU = "ACME"
        cert.get_subject().CN = cn
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(not_after)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

    return make_cert
