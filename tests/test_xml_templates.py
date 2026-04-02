from lxml import etree

from pyramid_saml2.xml_templates import NameIDTemplate, XmlTemplate, NAMESPACE_MAP
from pyramid_saml2.idp.xml_templates import (
    AssertionTemplate,
    AttributeStatementTemplate,
    AttributeTemplate,
    ResponseTemplate,
    SubjectTemplate,
)


class TestXmlTemplate:
    def test_element_creates_tag(self):
        template = XmlTemplate()
        template.namespace = 'saml'
        el = template.element('Test', text='hello')
        assert el.text == 'hello'
        assert 'Test' in el.tag

    def test_element_with_attrs(self):
        template = XmlTemplate()
        template.namespace = 'saml'
        el = template.element('Test', attrs={'Foo': 'bar'})
        assert el.get('Foo') == 'bar'

    def test_element_skips_none_attrs(self):
        template = XmlTemplate()
        template.namespace = 'saml'
        el = template.element('Test', attrs={'Foo': 'bar', 'Baz': None})
        assert el.get('Foo') == 'bar'
        assert el.get('Baz') is None

    def test_element_skips_none_children(self):
        template = XmlTemplate()
        template.namespace = 'saml'
        child = template.element('Child', text='x')
        el = template.element('Parent', children=[child, None])
        assert len(el) == 1

    def test_params_are_copied(self):
        params = {'key': 'value'}
        template = XmlTemplate(params)
        template.params['key'] = 'modified'
        assert params['key'] == 'value'


class TestNameIDTemplate:
    def test_generates_name_id(self):
        template = NameIDTemplate({
            'SUBJECT_FORMAT': 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
            'SP_NAME_QUALIFIER': 'http://sp.example.com',
            'SUBJECT': 'user@example.com',
        })
        xml_str = template.get_xml_string()
        assert 'user@example.com' in xml_str
        assert 'emailAddress' in xml_str


class TestAttributeTemplate:
    def test_generates_attribute(self):
        template = AttributeTemplate({
            'ATTRIBUTE_NAME': 'email',
            'ATTRIBUTE_VALUE': 'user@example.com',
        })
        xml_str = template.get_xml_string()
        assert 'email' in xml_str
        assert 'user@example.com' in xml_str


class TestAttributeStatementTemplate:
    def test_generates_statement_with_attrs(self):
        template = AttributeStatementTemplate({
            'ATTRIBUTES': {'name': 'Alice', 'role': 'admin'},
        })
        xml = template.xml
        assert xml is not None
        xml_str = etree.tostring(xml, encoding='unicode')
        assert 'Alice' in xml_str
        assert 'admin' in xml_str

    def test_returns_none_when_no_attrs(self):
        template = AttributeStatementTemplate({})
        assert template.xml is None

    def test_returns_none_when_empty_attrs(self):
        template = AttributeStatementTemplate({'ATTRIBUTES': {}})
        assert template.xml is None


ASSERTION_PARAMS = {
    'ASSERTION_ID': '_assertion_123',
    'AUDIENCE': 'http://sp.example.com',
    'IN_RESPONSE_TO': '_request_456',
    'AUTH_INSTANT': '2024-01-01T00:00:00Z',
    'ISSUE_INSTANT': '2024-01-01T00:00:00Z',
    'NOT_BEFORE': '2024-01-01T00:00:00Z',
    'NOT_ON_OR_AFTER': '2024-01-01T01:00:00Z',
    'SESSION_NOT_ON_OR_AFTER': '2024-01-01T08:00:00Z',
    'SP_NAME_QUALIFIER': 'http://sp.example.com',
    'SUBJECT': 'user@example.com',
    'SUBJECT_FORMAT': 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
    'ISSUER': 'http://idp.example.com',
    'ACS_URL': 'http://sp.example.com/saml/acs/',
    'REQUEST_ID': '_request_456',
    'DESTINATION': 'http://sp.example.com/saml/acs/',
    'PROVIDER_NAME': 'Test SP',
}


class TestAssertionTemplate:
    def test_generates_assertion(self):
        template = AssertionTemplate(ASSERTION_PARAMS)
        xml_str = template.get_xml_string()
        assert '_assertion_123' in xml_str
        assert 'user@example.com' in xml_str
        assert 'http://idp.example.com' in xml_str

    def test_assertion_with_attributes(self):
        params = {**ASSERTION_PARAMS, 'ATTRIBUTES': {'role': 'admin'}}
        template = AssertionTemplate(params)
        xml_str = template.get_xml_string()
        assert 'admin' in xml_str

    def test_assertion_id_parameter(self):
        assert AssertionTemplate.id_parameter == 'ASSERTION_ID'


class TestResponseTemplate:
    def test_generates_response(self):
        assertion = AssertionTemplate(ASSERTION_PARAMS)
        response_params = {
            'ISSUE_INSTANT': '2024-01-01T00:00:00Z',
            'RESPONSE_ID': '_response_789',
            'IN_RESPONSE_TO': '_request_456',
            'ACS_URL': 'http://sp.example.com/saml/acs/',
            'ISSUER': 'http://idp.example.com',
            'REQUEST_ID': '_request_456',
            'DESTINATION': 'http://sp.example.com/saml/acs/',
            'PROVIDER_NAME': 'Test SP',
        }
        template = ResponseTemplate(response_params, assertion)
        xml_str = template.get_xml_string()
        assert '_response_789' in xml_str
        assert 'Success' in xml_str
        assert 'http://idp.example.com' in xml_str

    def test_response_id_parameter(self):
        assert ResponseTemplate.id_parameter == 'RESPONSE_ID'
