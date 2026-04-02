import base64
import zlib
from pathlib import Path

import pytest
from lxml import etree
from pyramid import testing
from pyramid.session import SignedCookieSessionFactory

from pyramid_saml2.idp import IdentityProvider, SPHandler
from pyramid_saml2.utils import certificate_from_file, private_key_from_file
from pyramid_saml2.xml_templates import NAMESPACE_MAP


KEY_DIR = Path(__file__).parent / 'keys' / 'sample'

IDP_CERTIFICATE = certificate_from_file(KEY_DIR / 'idp-certificate.pem')
IDP_PRIVATE_KEY = private_key_from_file(KEY_DIR / 'idp-private-key.pem')
SP_CERTIFICATE = certificate_from_file(KEY_DIR / 'sp-certificate.pem')


AUTHN_REQUEST_TEMPLATE = '''\
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_test_request_id"
                    Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z"
                    Destination="{destination}"
                    AssertionConsumerServiceURL="{acs_url}"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    ProviderName="Test SP">
    <saml:Issuer>{entity_id}</saml:Issuer>
</samlp:AuthnRequest>'''


LOGOUT_REQUEST_TEMPLATE = '''\
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="_test_logout_id"
                     Version="2.0"
                     IssueInstant="2024-01-01T00:00:00Z"
                     Destination="{destination}">
    <saml:Issuer>{entity_id}</saml:Issuer>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"
                 SPNameQualifier="{entity_id}">user@example.com</saml:NameID>
</samlp:LogoutRequest>'''


class User:
    def __init__(self, username, email):
        self.username = username
        self.email = email


TEST_USER = User('testuser', 'test@example.com')


class SampleIdentityProvider(IdentityProvider):
    def login_required(self):
        pass

    def is_user_logged_in(self):
        return 'user' in self.request.session

    def logout(self):
        del self.request.session['user']

    def get_current_user(self):
        return TEST_USER


class SampleSPHandler(SPHandler):
    pass


def make_saml_request(xml_string):
    """Base64-encode an XML string for use as a SAMLRequest parameter."""
    return base64.b64encode(xml_string.encode('utf-8')).decode('utf-8')


def deflate_and_encode(xml_string):
    """Deflate and base64-encode an XML string for use as a SAMLRequest parameter."""
    compressed = zlib.compress(xml_string.encode('utf-8'))
    # Strip zlib header (first 2 bytes) and checksum (last 4 bytes)
    deflated = compressed[2:-4]
    return base64.b64encode(deflated).decode('utf-8')


SP_ENTITY_ID = 'http://sp.example.com/saml/metadata.xml'
SP_ACS_URL = 'http://sp.example.com/saml/acs/'


@pytest.fixture
def settings():
    return {
        'SAML2_IDP': {
            'autosubmit': True,
            'certificate': IDP_CERTIFICATE,
            'private_key': IDP_PRIVATE_KEY,
        },
        'SAML2_SERVICE_PROVIDERS': [
            {
                'CLASS': 'tests.conftest.SampleSPHandler',  # dotted path for import_string
                'OPTIONS': {
                    'display_name': 'Test SP',
                    'entity_id': SP_ENTITY_ID,
                    'acs_url': SP_ACS_URL,
                    'certificate': SP_CERTIFICATE,
                },
            }
        ],
    }


@pytest.fixture
def pyramid_config(settings):
    config = testing.setUp(settings=settings)
    session_factory = SignedCookieSessionFactory('testsecret')
    config.set_session_factory(session_factory)
    config.commit()
    config.include('pyramid_saml2')
    config.configure_saml2_idp(SampleIdentityProvider)
    config.commit()
    yield config
    testing.tearDown()


@pytest.fixture
def app(pyramid_config):
    from webtest import TestApp
    return TestApp(pyramid_config.make_wsgi_app())


@pytest.fixture
def dummy_request(pyramid_config):
    request = testing.DummyRequest()
    request.registry = pyramid_config.registry
    request.session = {}
    return request


@pytest.fixture
def idp(dummy_request):
    return SampleIdentityProvider(dummy_request)


@pytest.fixture
def sp_handler(idp):
    return SampleSPHandler(
        idp,
        entity_id=SP_ENTITY_ID,
        acs_url=SP_ACS_URL,
        certificate=SP_CERTIFICATE,
        display_name='Test SP',
    )


@pytest.fixture
def authn_request_xml():
    def _make(destination='http://localhost/saml/login/',
              entity_id=SP_ENTITY_ID,
              acs_url=SP_ACS_URL):
        return AUTHN_REQUEST_TEMPLATE.format(
            destination=destination,
            entity_id=entity_id,
            acs_url=acs_url,
        )
    return _make


@pytest.fixture
def logout_request_xml():
    def _make(destination='http://localhost/saml/logout/',
              entity_id=SP_ENTITY_ID):
        return LOGOUT_REQUEST_TEMPLATE.format(
            destination=destination,
            entity_id=entity_id,
        )
    return _make
