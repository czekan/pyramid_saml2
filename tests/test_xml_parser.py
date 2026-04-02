import pytest

from pyramid_saml2.xml_parser import XmlParser


class ConcreteParser(XmlParser):
    """Minimal concrete implementation for testing the base class."""
    def is_signed(self):
        return False


class SignedParser(XmlParser):
    """Parser that reports the document as signed."""
    def is_signed(self):
        return True


class TestXmlParser:
    def test_parses_valid_xml(self):
        xml = b'<root><child>text</child></root>'
        parser = ConcreteParser(xml, certificate=None)
        assert parser.xml_tree is not None
        assert parser.xml_tree.tag == 'root'

    def test_invalid_xml_raises_value_error(self):
        with pytest.raises(ValueError, match="Could not parse"):
            ConcreteParser(b'not xml', certificate=None)

    def test_signed_without_certificate_raises(self):
        xml = b'<root><child>text</child></root>'
        with pytest.raises(ValueError, match="no certificate is configured"):
            SignedParser(xml, certificate=None)

    def test_stores_certificate(self):
        from tests.conftest import SP_CERTIFICATE
        xml = b'<root><child>text</child></root>'
        parser = ConcreteParser(xml, certificate=SP_CERTIFICATE)
        assert parser.certificate is SP_CERTIFICATE

    def test_none_certificate_stays_none(self):
        xml = b'<root><child>text</child></root>'
        parser = ConcreteParser(xml, certificate=None)
        assert parser.certificate is None

    def test_xpath_xml_tree(self):
        xml = b'<root><child>text</child></root>'
        parser = ConcreteParser(xml, certificate=None)
        result = parser._xpath_xml_tree('/root/child')
        assert len(result) == 1
        assert result[0].text == 'text'
