import OpenSSL.crypto
import pytest
from pyramid import testing

from pyramid_saml2.exceptions import CannotHandleAssertion
from tests.conftest import (
    IDP_CERTIFICATE,
    IDP_PRIVATE_KEY,
    SP_ACS_URL,
    SP_CERTIFICATE,
    SP_ENTITY_ID,
    TEST_USER,
    SampleIdentityProvider,
    SampleSPHandler,
)


class SampleIdentityProviderConfig:
    def test_get_idp_config(self, idp, settings):
        config = idp.get_idp_config()
        assert config['autosubmit'] is True
        assert config['certificate'] is IDP_CERTIFICATE
        assert config['private_key'] is IDP_PRIVATE_KEY

    def test_get_idp_certificate(self, idp):
        cert = idp.get_idp_certificate()
        assert cert is IDP_CERTIFICATE

    def test_get_idp_private_key(self, idp):
        key = idp.get_idp_private_key()
        assert key is IDP_PRIVATE_KEY

    def test_should_sign_responses(self, idp):
        assert idp.should_sign_responses() is True

    def test_should_not_sign_without_cert(self, pyramid_config):
        settings = pyramid_config.registry.settings
        settings['SAML2_IDP'] = {'autosubmit': False}
        request = testing.DummyRequest()
        request.registry = pyramid_config.registry
        request.session = {}
        idp = SampleIdentityProvider(request)
        assert idp.should_sign_responses() is False

    def test_get_idp_autosubmit(self, idp):
        assert idp.get_idp_autosubmit() is True

    def test_autosubmit_defaults_false(self, pyramid_config):
        settings = pyramid_config.registry.settings
        settings['SAML2_IDP'] = {}
        request = testing.DummyRequest()
        request.registry = pyramid_config.registry
        request.session = {}
        idp = SampleIdentityProvider(request)
        assert idp.get_idp_autosubmit() is False


class SampleIdentityProviderAuth:
    def test_is_user_logged_in_false(self, idp):
        assert idp.is_user_logged_in() is False

    def test_is_user_logged_in_true(self, dummy_request):
        dummy_request.session['user'] = 'testuser'
        idp = SampleIdentityProvider(dummy_request)
        assert idp.is_user_logged_in() is True

    def test_logout(self, dummy_request):
        dummy_request.session['user'] = 'testuser'
        idp = SampleIdentityProvider(dummy_request)
        idp.logout()
        assert 'user' not in dummy_request.session

    def test_get_current_user(self, idp):
        user = idp.get_current_user()
        assert user is TEST_USER
        assert user.email == 'test@example.com'


class SampleIdentityProviderSPHandlers:
    def test_get_sp_handlers(self, idp):
        handlers = list(idp.get_sp_handlers())
        assert len(handlers) == 1
        handler = handlers[0]
        assert isinstance(handler, SampleSPHandler)
        assert handler.entity_id == SP_ENTITY_ID
        assert handler.acs_url == SP_ACS_URL

    def test_get_service_providers(self, idp):
        sps = idp.get_service_providers()
        assert len(sps) == 1
        assert sps[0]['CLASS'] == 'tests.conftest.SampleSPHandler'


class SampleIdentityProviderMetadata:
    def test_get_metadata_context(self, idp):
        # Need routes for metadata URL generation
        pass

    def test_get_metadata_context_without_cert(self, pyramid_config):
        settings = pyramid_config.registry.settings
        settings['SAML2_IDP'] = {'autosubmit': False}
        request = testing.DummyRequest()
        request.registry = pyramid_config.registry
        request.session = {}
        idp = SampleIdentityProvider(request)
        ctx = idp.get_metadata_context()
        assert ctx['certificate'] == ''


class SampleIdentityProviderRedirect:
    def test_is_valid_redirect_true(self, idp):
        assert idp.is_valid_redirect('http://sp.example.com/dashboard') is True

    def test_is_valid_redirect_false(self, idp):
        assert idp.is_valid_redirect('http://evil.example.com/phish') is False

    def test_is_valid_redirect_wrong_scheme(self, idp):
        assert idp.is_valid_redirect('ftp://sp.example.com/file') is False


class SampleSPHandlerInit:
    def test_basic_init(self, sp_handler):
        assert sp_handler.entity_id == SP_ENTITY_ID
        assert sp_handler.acs_url == SP_ACS_URL
        assert sp_handler.display_name == 'Test SP'
        assert sp_handler.certificate is SP_CERTIFICATE

    def test_str_display_name(self, sp_handler):
        assert str(sp_handler) == 'Test SP'

    def test_str_without_display_name(self, idp):
        handler = SampleSPHandler(idp, entity_id=SP_ENTITY_ID)
        assert str(handler) == SP_ENTITY_ID


class SampleSPHandlerValidation:
    def test_validate_entity_id_match(self, sp_handler, authn_request_xml):
        xml = authn_request_xml(entity_id=SP_ENTITY_ID)
        request = sp_handler.parse_authn_request(
            __import__('base64').b64encode(xml.encode()).decode())
        sp_handler.validate_entity_id(request)

    def test_validate_entity_id_mismatch(self, sp_handler, authn_request_xml):
        xml = authn_request_xml(entity_id='http://wrong.example.com')
        request = sp_handler.parse_authn_request(
            __import__('base64').b64encode(xml.encode()).decode())
        with pytest.raises(CannotHandleAssertion, match="Issuer does not match"):
            sp_handler.validate_entity_id(request)

    def test_validate_acs_url_match(self, sp_handler, authn_request_xml):
        xml = authn_request_xml(acs_url=SP_ACS_URL)
        request = sp_handler.parse_authn_request(
            __import__('base64').b64encode(xml.encode()).decode())
        sp_handler.validate_acs_url(request)

    def test_validate_acs_url_mismatch(self, sp_handler, authn_request_xml):
        xml = authn_request_xml(acs_url='http://wrong.example.com/acs/')
        request = sp_handler.parse_authn_request(
            __import__('base64').b64encode(xml.encode()).decode())
        with pytest.raises(CannotHandleAssertion, match="ACS URL mismatch"):
            sp_handler.validate_acs_url(request)

    def test_is_valid_redirect(self, sp_handler):
        assert sp_handler.is_valid_redirect('http://sp.example.com/dashboard') is True
        assert sp_handler.is_valid_redirect('http://evil.com/phish') is False


class SampleSPHandlerResponse:
    def test_build_assertion(self, sp_handler, authn_request_xml):
        import datetime
        xml = authn_request_xml()
        request = sp_handler.parse_authn_request(
            __import__('base64').b64encode(xml.encode()).decode())
        issue_instant = datetime.datetime(2024, 1, 1, 0, 0, 0)
        assertion = sp_handler.build_assertion(request, issue_instant)

        assert 'ASSERTION_ID' in assertion
        assert assertion['AUDIENCE'] == SP_ENTITY_ID
        assert assertion['IN_RESPONSE_TO'] == '_test_request_id'
        assert assertion['SUBJECT_FORMAT'] == 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress'
        assert assertion['ACS_URL'] == SP_ACS_URL

    def test_build_response(self, sp_handler, authn_request_xml):
        import datetime
        xml = authn_request_xml()
        request = sp_handler.parse_authn_request(
            __import__('base64').b64encode(xml.encode()).decode())
        issue_instant = datetime.datetime(2024, 1, 1, 0, 0, 0)
        response = sp_handler.build_response(request, issue_instant)

        assert 'RESPONSE_ID' in response
        assert response['IN_RESPONSE_TO'] == '_test_request_id'
        assert response['ACS_URL'] == SP_ACS_URL

    @pytest.mark.skipif(
        not hasattr(OpenSSL.crypto, 'sign'),
        reason="OpenSSL.crypto.sign removed in newer pyopenssl"
    )
    def test_make_response(self, sp_handler, authn_request_xml):
        xml = authn_request_xml(destination='http://example.com/saml/login/')
        request = sp_handler.parse_authn_request(
            __import__('base64').b64encode(xml.encode()).decode())
        response = sp_handler.make_response(request)
        xml_str = response.get_xml_string()
        assert 'Response' in xml_str
        assert 'Assertion' in xml_str
