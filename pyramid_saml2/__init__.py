import logging
import os

from pyramid.config import Configurator
from pyramid.interfaces import ISessionFactory

from pyramid_saml2.idp.views import login_begin, login_process, logout, metadata

__VERSION__ = '0.1'


log = logging.getLogger('pyramid_saml2')
"""logging.Logger: Logger instance for log output."""


def configure_saml2_idp(config, idp_cls: 'idp.IdentityProvider'):

    # Put IdP class in registry
    config.registry['saml2_idp_cls'] = idp_cls

    config.add_route('pyramid_saml2_idp_login_begin', pattern='/saml/login/')
    config.add_view(login_begin, 'pyramid_saml2_idp_login_begin')
    
    config.add_route('pyramid_saml2_idp_login_process', pattern='/saml/login/process/')
    config.add_view(login_process, 'pyramid_saml2_idp_login_process')

    config.add_route('pyramid_saml2_idp_logout', pattern='/saml/logout/')
    config.add_view(logout, 'pyramid_saml2_idp_logout')

    config.add_route('pyramid_saml2_idp_metadata', pattern='/saml/metadata.xml')
    config.add_view(metadata, 'pyramid_saml2_idp_metadata')

    config.scan("pyramid_saml2.idp.views")


def includeme(config: Configurator) -> None:
    """Include this library in an existing Pyramid application.

    Args:
        config (pyramid.config.Configurator): The configuration of the
            existing Pyramid application.
    """

    # Set log level through env variable
    log_level = '{0}'.format(os.environ.get('PYRAMID_SAML2_LOG_LEVEL')).lower()
    if log_level == 'error':
        log.setLevel(logging.ERROR)
    elif log_level == 'warning':
        log.setLevel(logging.WARNING)
    elif log_level == 'debug':
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    config.include('pyramid_jinja2')
    config.add_jinja2_renderer(".html")

    factory = config.registry.queryUtility(ISessionFactory)
    if factory is None:
        raise AttributeError(
            'No session factory registered.'
            'Please register one first.'
        )

    config.add_directive('configure_saml2_idp', configure_saml2_idp)
