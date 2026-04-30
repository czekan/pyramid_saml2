import base64
from pathlib import Path

import pytest

from pyramid_saml2.signing import (
    RsaSha1Signer,
    RsaSha256Signer,
    Sha1Digester,
    Sha256Digester,
    sign_query_parameters,
)
from pyramid_saml2.utils import private_key_from_file


KEY_DIR = Path(__file__).parent / 'keys' / 'sample'

class TestDigesters:
    def test_sha1_produces_digest(self):
        digester = Sha1Digester()
        result = digester(b'Hello, world!')
        assert isinstance(result, str)
        assert len(result) > 0
        # SHA1 digest is 20 bytes, base64 encoded = 28 chars
        assert len(base64.b64decode(result)) == 20

    def test_sha1_deterministic(self):
        digester = Sha1Digester()
        assert digester(b'test') == digester(b'test')

    def test_sha1_different_inputs(self):
        digester = Sha1Digester()
        assert digester(b'foo') != digester(b'bar')

    def test_sha256_produces_digest(self):
        digester = Sha256Digester()
        result = digester(b'Hello, world!')
        assert isinstance(result, str)
        # SHA256 digest is 32 bytes
        assert len(base64.b64decode(result)) == 32

    def test_sha1_uri(self):
        assert 'sha1' in Sha1Digester.uri

    def test_sha256_uri(self):
        assert 'sha256' in Sha256Digester.uri


class TestSigners:
    @pytest.fixture
    def private_key(self):
        return private_key_from_file(KEY_DIR / 'idp-private-key.pem')

    def test_rsa_sha1_signs(self, private_key):
        signer = RsaSha1Signer(private_key)
        result = signer(b'test data')
        assert isinstance(result, str)
        assert len(result) > 0

    def test_rsa_sha1_deterministic(self, private_key):
        signer = RsaSha1Signer(private_key)
        assert signer(b'test') == signer(b'test')

    def test_rsa_sha256_signs(self, private_key):
        signer = RsaSha256Signer(private_key)
        result = signer(b'test data')
        assert isinstance(result, str)
        assert len(result) > 0

    def test_rsa_sha1_uri(self):
        assert 'rsa-sha1' in RsaSha1Signer.uri

    def test_rsa_sha256_uri(self):
        assert 'rsa-sha256' in RsaSha256Signer.uri


class TestSignQueryParameters:
    def test_signs_parameters(self):
        key = private_key_from_file(KEY_DIR / 'idp-private-key.pem')
        signer = RsaSha1Signer(key)
        bits = [('SAMLRequest', 'abc'), ('RelayState', 'xyz')]
        result = sign_query_parameters(signer, bits)

        assert 'SAMLRequest=abc' in result
        assert 'RelayState=xyz' in result
        assert 'SigAlg=' in result
        assert 'Signature=' in result
