import pytest
from pyramid import testing
from pyramid.session import SignedCookieSessionFactory

from tests.conftest import IDP_CERTIFICATE, IDP_PRIVATE_KEY, SampleIdentityProvider


class TestIncludeMe:
    def test_include_registers_directive(self):
        config = testing.setUp(settings={
            'SAML2_IDP': {
                'certificate': IDP_CERTIFICATE,
                'private_key': IDP_PRIVATE_KEY,
            },
            'SAML2_SERVICE_PROVIDERS': [],
        })
        session_factory = SignedCookieSessionFactory('secret')
        config.set_session_factory(session_factory)
        config.commit()
        config.include('pyramid_saml2')
        assert hasattr(config, 'configure_saml2_idp')
        testing.tearDown()

    def test_include_without_session_raises(self):
        config = testing.setUp(settings={
            'SAML2_IDP': {},
            'SAML2_SERVICE_PROVIDERS': [],
        })
        with pytest.raises(AttributeError, match="No session factory"):
            config.include('pyramid_saml2')
            config.commit()
        testing.tearDown()

    def test_configure_registers_routes(self):
        config = testing.setUp(settings={
            'SAML2_IDP': {
                'certificate': IDP_CERTIFICATE,
                'private_key': IDP_PRIVATE_KEY,
            },
            'SAML2_SERVICE_PROVIDERS': [],
        })
        session_factory = SignedCookieSessionFactory('secret')
        config.set_session_factory(session_factory)
        config.commit()
        config.include('pyramid_saml2')
        config.configure_saml2_idp(SampleIdentityProvider)
        config.commit()

        introspector = config.registry.introspector
        routes = {
            intr['introspectable']['name']
            for intr in introspector.get_category('routes', [])
        }
        assert 'pyramid_saml2_idp_login_begin' in routes
        assert 'pyramid_saml2_idp_login_process' in routes
        assert 'pyramid_saml2_idp_logout' in routes
        assert 'pyramid_saml2_idp_metadata' in routes
        testing.tearDown()

    def test_idp_class_in_registry(self):
        config = testing.setUp(settings={
            'SAML2_IDP': {
                'certificate': IDP_CERTIFICATE,
                'private_key': IDP_PRIVATE_KEY,
            },
            'SAML2_SERVICE_PROVIDERS': [],
        })
        session_factory = SignedCookieSessionFactory('secret')
        config.set_session_factory(session_factory)
        config.commit()
        config.include('pyramid_saml2')
        config.configure_saml2_idp(SampleIdentityProvider)
        config.commit()

        assert config.registry['saml2_idp_cls'] is SampleIdentityProvider
        testing.tearDown()
