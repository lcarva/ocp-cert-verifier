from base64 import b64encode
from unittest.mock import patch

from ocp_cert_verifier import verify


NOT_AFTER_DAYS = 24*60*60


@patch('ocp_cert_verifier.core.get_ocp_secrets')
def test_no_secrets(mock_get_ocp_secrets):
    mock_get_ocp_secrets.return_value = []
    assert verify('myproject', 30) == []


@patch('ocp_cert_verifier.core.get_ocp_secrets')
def test_single_cert(mock_get_ocp_secrets, generate_cert):

    cert_30_days = generate_cert('30days', 30 * NOT_AFTER_DAYS)
    mock_get_ocp_secrets.return_value = [
        {
            'type': 'Opaque',
            'metadata': {
                'name': 'mysecret'
            },
            'data': {
                'mycert': b64encode(cert_30_days)
            }
        }
    ]

    certs = verify('myproject', 29)
    assert len(certs) == 1
    assert certs[0].expires_soon is False
    assert certs[0].name == 'myproject:mysecret:mycert'

    certs = verify('myproject', 31)
    assert len(certs) == 1
    assert certs[0].expires_soon is True
    assert certs[0].name == 'myproject:mysecret:mycert'


@patch('ocp_cert_verifier.core.get_ocp_secrets')
def test_multiple_certs(mock_get_ocp_secrets, generate_cert):

    cert_30_days = generate_cert('30days', 30 * NOT_AFTER_DAYS)
    cert_35_days = generate_cert('35days', 35 * NOT_AFTER_DAYS)
    mock_get_ocp_secrets.return_value = [
        {
            'type': 'Opaque',
            'metadata': {
                'name': 'mysecret'
            },
            'data': {
                'mycert': b64encode(cert_30_days),
                'myothercert': b64encode(cert_35_days),
            }
        }
    ]

    certs = verify('myproject', 29)
    assert len(certs) == 2
    assert certs[0].expires_soon is False
    assert certs[0].name == 'myproject:mysecret:mycert'
    assert certs[1].expires_soon is False
    assert certs[1].name == 'myproject:mysecret:myothercert'

    certs = verify('myproject', 31)
    assert len(certs) == 2
    assert certs[0].expires_soon is True
    assert certs[0].name == 'myproject:mysecret:mycert'
    assert certs[1].expires_soon is False
    assert certs[1].name == 'myproject:mysecret:myothercert'

    certs = verify('myproject', 36)
    assert len(certs) == 2
    assert certs[0].expires_soon is True
    assert certs[0].name == 'myproject:mysecret:mycert'
    assert certs[1].expires_soon is True
    assert certs[1].name == 'myproject:mysecret:myothercert'


@patch('ocp_cert_verifier.core.get_ocp_secrets')
def test_cert_chain(mock_get_ocp_secrets, generate_cert):

    cert_30_days = generate_cert('30days', 30 * NOT_AFTER_DAYS)
    cert_35_days = generate_cert('35days', 35 * NOT_AFTER_DAYS)
    chain = b'\n'.join([cert_30_days, cert_35_days])
    mock_get_ocp_secrets.return_value = [
        {
            'type': 'Opaque',
            'metadata': {
                'name': 'mysecret'
            },
            'data': {
                'mycert': b64encode(chain),
            }
        }
    ]

    certs = verify('myproject', 29)
    assert len(certs) == 2
    assert certs[0].expires_soon is False
    assert certs[0].name == 'myproject:mysecret:mycert'
    assert certs[1].expires_soon is False
    assert certs[1].name == 'myproject:mysecret:mycert'

    certs = verify('myproject', 31)
    assert len(certs) == 2
    assert certs[0].expires_soon is True
    assert certs[0].name == 'myproject:mysecret:mycert'
    assert certs[1].expires_soon is False
    assert certs[1].name == 'myproject:mysecret:mycert'

    certs = verify('myproject', 36)
    assert len(certs) == 2
    assert certs[0].expires_soon is True
    assert certs[0].name == 'myproject:mysecret:mycert'
    assert certs[1].expires_soon is True
    assert certs[1].name == 'myproject:mysecret:mycert'


@patch('ocp_cert_verifier.core.get_ocp_secrets')
def test_multiple_secrets(mock_get_ocp_secrets, generate_cert):
    cert_30_days = generate_cert('30days', 30 * NOT_AFTER_DAYS)
    cert_35_days = generate_cert('35days', 35 * NOT_AFTER_DAYS)
    mock_get_ocp_secrets.return_value = [
        {
            'type': 'Opaque',
            'metadata': {
                'name': 'mysecret'
            },
            'data': {
                'mycert': b64encode(cert_30_days),
            }
        },
        {
            'type': 'Opaque',
            'metadata': {
                'name': 'myothersecret'
            },
            'data': {
                'myothercert': b64encode(cert_35_days),
            }
        }
    ]

    certs = verify('myproject', 29)
    assert len(certs) == 2
    assert certs[0].expires_soon is False
    assert certs[0].name == 'myproject:mysecret:mycert'
    assert certs[1].expires_soon is False
    assert certs[1].name == 'myproject:myothersecret:myothercert'

    certs = verify('myproject', 31)
    assert len(certs) == 2
    assert certs[0].expires_soon is True
    assert certs[0].name == 'myproject:mysecret:mycert'
    assert certs[1].expires_soon is False
    assert certs[1].name == 'myproject:myothersecret:myothercert'

    certs = verify('myproject', 36)
    assert len(certs) == 2
    assert certs[0].expires_soon is True
    assert certs[0].name == 'myproject:mysecret:mycert'
    assert certs[1].expires_soon is True
    assert certs[1].name == 'myproject:myothersecret:myothercert'
