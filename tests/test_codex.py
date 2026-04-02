import base64
import zlib

import pytest


from pyramid_saml2.codex import (
    decode_base64_and_inflate,
    decode_saml_xml,
    deflate_and_base64_encode,
)


class TestDeflateAndBase64Encode:
    def test_roundtrip_string(self):
        original = 'Hello, SAML world!'
        encoded = deflate_and_base64_encode(original)
        decoded = decode_base64_and_inflate(encoded)
        assert decoded == original.encode('utf-8')

    def test_roundtrip_bytes(self):
        original = b'<xml>test</xml>'
        encoded = deflate_and_base64_encode(original)
        decoded = decode_base64_and_inflate(encoded)
        assert decoded == original

    def test_bytes_input(self):
        encoded = deflate_and_base64_encode(b'test data')
        decoded = decode_base64_and_inflate(encoded)
        assert decoded == b'test data'

    def test_decode_accepts_bytes(self):
        encoded = deflate_and_base64_encode('test')
        decoded = decode_base64_and_inflate(encoded)
        assert decoded == b'test'


class TestDecodeSamlXml:
    def test_decodes_base64_xml(self):
        xml = b'<saml>test</saml>'
        encoded = base64.b64encode(xml).decode('utf-8')
        assert decode_saml_xml(encoded) == xml

    def test_decodes_deflated_xml(self):
        xml = '<saml>test</saml>'
        encoded = deflate_and_base64_encode(xml)
        assert decode_saml_xml(encoded) == xml.encode('utf-8')

    def test_raises_for_non_xml(self):
        encoded = base64.b64encode(b'not xml at all').decode('utf-8')
        with pytest.raises((ValueError, zlib.error)):
            decode_saml_xml(encoded)
