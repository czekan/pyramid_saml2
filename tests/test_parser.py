import pytest

from pyramid_saml2.idp.parser import AuthnRequestParser, LogoutRequestParser


class TestAuthnRequestParser:
    def make_xml(self, **overrides):
        defaults = {
            'id': '_test_id_123',
            'version': '2.0',
            'issue_instant': '2024-01-01T00:00:00Z',
            'destination': 'http://idp.example.com/saml/login/',
            'acs_url': 'http://sp.example.com/saml/acs/',
            'protocol_binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'provider_name': 'Test SP',
            'issuer': 'http://sp.example.com/metadata',
        }
        defaults.update(overrides)
        return f'''\
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{defaults['id']}"
                    Version="{defaults['version']}"
                    IssueInstant="{defaults['issue_instant']}"
                    Destination="{defaults['destination']}"
                    AssertionConsumerServiceURL="{defaults['acs_url']}"
                    ProtocolBinding="{defaults['protocol_binding']}"
                    ProviderName="{defaults['provider_name']}">
    <saml:Issuer>{defaults['issuer']}</saml:Issuer>
</samlp:AuthnRequest>'''.encode('utf-8')

    def test_parse_issuer(self):
        parser = AuthnRequestParser(self.make_xml(), certificate=None)
        assert parser.issuer == 'http://sp.example.com/metadata'

    def test_parse_request_id(self):
        parser = AuthnRequestParser(self.make_xml(), certificate=None)
        assert parser.request_id == '_test_id_123'

    def test_parse_destination(self):
        parser = AuthnRequestParser(self.make_xml(), certificate=None)
        assert parser.destination == 'http://idp.example.com/saml/login/'

    def test_parse_acs_url(self):
        parser = AuthnRequestParser(self.make_xml(), certificate=None)
        assert parser.acs_url == 'http://sp.example.com/saml/acs/'

    def test_parse_version(self):
        parser = AuthnRequestParser(self.make_xml(), certificate=None)
        assert parser.version == '2.0'

    def test_parse_issue_instant(self):
        parser = AuthnRequestParser(self.make_xml(), certificate=None)
        assert parser.issue_instant == '2024-01-01T00:00:00Z'

    def test_parse_protocol_binding(self):
        parser = AuthnRequestParser(self.make_xml(), certificate=None)
        assert parser.protocol_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'

    def test_parse_provider_name(self):
        parser = AuthnRequestParser(self.make_xml(), certificate=None)
        assert parser.provider_name == 'Test SP'

    def test_missing_destination_returns_empty(self):
        xml = b'''\
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_test_id"
                    Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z"
                    AssertionConsumerServiceURL="http://sp.example.com/acs/"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>http://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>'''
        parser = AuthnRequestParser(xml, certificate=None)
        assert parser.destination == ''

    def test_missing_provider_name_returns_empty(self):
        xml = b'''\
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_test_id"
                    Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z"
                    Destination="http://idp.example.com/login/"
                    AssertionConsumerServiceURL="http://sp.example.com/acs/"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>http://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>'''
        parser = AuthnRequestParser(xml, certificate=None)
        assert parser.provider_name == ''

    def test_missing_required_issuer_raises(self):
        xml = b'''\
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_test_id"
                    Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z"
                    AssertionConsumerServiceURL="http://sp.example.com/acs/"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
</samlp:AuthnRequest>'''
        parser = AuthnRequestParser(xml, certificate=None)
        with pytest.raises(ValueError, match="Missing required.*Issuer"):
            _ = parser.issuer

    def test_missing_required_id_raises(self):
        xml = b'''\
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z"
                    AssertionConsumerServiceURL="http://sp.example.com/acs/"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>http://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>'''
        parser = AuthnRequestParser(xml, certificate=None)
        with pytest.raises(ValueError, match="Missing required.*ID"):
            _ = parser.request_id

    def test_is_signed_false_for_unsigned(self):
        parser = AuthnRequestParser(self.make_xml(), certificate=None)
        assert parser.is_signed() is False

    def test_invalid_xml_raises(self):
        with pytest.raises(ValueError, match="Could not parse"):
            AuthnRequestParser(b'not xml', certificate=None)


class TestLogoutRequestParser:
    def make_xml(self, **overrides):
        defaults = {
            'id': '_logout_test_id',
            'version': '2.0',
            'issue_instant': '2024-01-01T00:00:00Z',
            'destination': 'http://idp.example.com/saml/logout/',
            'issuer': 'http://sp.example.com/metadata',
            'nameid': 'user@example.com',
            'nameid_format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
        }
        defaults.update(overrides)
        return f'''\
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="{defaults['id']}"
                     Version="{defaults['version']}"
                     IssueInstant="{defaults['issue_instant']}"
                     Destination="{defaults['destination']}">
    <saml:Issuer>{defaults['issuer']}</saml:Issuer>
    <saml:NameID Format="{defaults['nameid_format']}"
                 SPNameQualifier="{defaults['issuer']}">{defaults['nameid']}</saml:NameID>
</samlp:LogoutRequest>'''.encode('utf-8')

    def test_parse_issuer(self):
        parser = LogoutRequestParser(self.make_xml(), certificate=None)
        assert parser.issuer == 'http://sp.example.com/metadata'

    def test_parse_request_id(self):
        parser = LogoutRequestParser(self.make_xml(), certificate=None)
        assert parser.request_id == '_logout_test_id'

    def test_parse_destination(self):
        parser = LogoutRequestParser(self.make_xml(), certificate=None)
        assert parser.destination == 'http://idp.example.com/saml/logout/'

    def test_missing_destination_returns_none(self):
        xml = b'''\
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="_test_id"
                     Version="2.0"
                     IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>http://sp.example.com</saml:Issuer>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">user@example.com</saml:NameID>
</samlp:LogoutRequest>'''
        parser = LogoutRequestParser(xml, certificate=None)
        assert parser.destination is None

    def test_parse_nameid(self):
        parser = LogoutRequestParser(self.make_xml(), certificate=None)
        assert parser.nameid == 'user@example.com'

    def test_parse_nameid_format(self):
        parser = LogoutRequestParser(self.make_xml(), certificate=None)
        assert parser.nameid_format == 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress'

    def test_parse_version(self):
        parser = LogoutRequestParser(self.make_xml(), certificate=None)
        assert parser.version == '2.0'

    def test_is_signed_false_for_unsigned(self):
        parser = LogoutRequestParser(self.make_xml(), certificate=None)
        assert parser.is_signed() is False

    def test_missing_required_issuer_raises(self):
        xml = b'''\
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="_test_id"
                     Version="2.0"
                     IssueInstant="2024-01-01T00:00:00Z">
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">user@example.com</saml:NameID>
</samlp:LogoutRequest>'''
        parser = LogoutRequestParser(xml, certificate=None)
        with pytest.raises(ValueError, match="Missing required.*Issuer"):
            _ = parser.issuer
