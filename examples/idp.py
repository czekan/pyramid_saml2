#!/usr/bin/env python3
import attr
import logging
from pathlib import Path

from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.httpexceptions import HTTPFound
from pyramid.response import Response
from pyramid.session import SignedCookieSessionFactory
from pyramid.view import view_config, view_defaults

from pyramid_saml2.idp import IdentityProvider, SPHandler
from pyramid_saml2.utils import certificate_from_file, private_key_from_file


logger = logging.getLogger(__name__)


PORT = 8000

KEY_DIR = Path(__file__).parent.parent / 'tests' / 'keys' / 'sample'
IDP_CERTIFICATE_FILE = KEY_DIR / 'idp-certificate.pem'
IDP_PRIVATE_KEY_FILE = KEY_DIR / 'idp-private-key.pem'

IDP_CERTIFICATE = certificate_from_file(IDP_CERTIFICATE_FILE)
IDP_PRIVATE_KEY = private_key_from_file(IDP_PRIVATE_KEY_FILE)

SP_CERTIFICATE_FILE = KEY_DIR / 'sp-certificate.pem'
SP_CERTIFICATE = certificate_from_file(SP_CERTIFICATE_FILE)


class AttributeSPHandler(SPHandler):
    def build_assertion(self, request, *args, **kwargs):
        return {
            **super().build_assertion(request, *args, **kwargs),
            'ATTRIBUTES': {
                'foo': 'bar',
            },
        }


settings = {
    'SERVER_NAME': 'localhost:8000',
    'SAML2_IDP': {
        'autosubmit': True,
        'certificate': IDP_CERTIFICATE,
        'private_key': IDP_PRIVATE_KEY,
    },
    'SAML2_SERVICE_PROVIDERS': [
        {
            'CLASS': 'examples.idp.AttributeSPHandler',
            'OPTIONS': {
                'display_name': 'Example Service Provider',
                'entity_id': 'http://localhost:9000/saml/metadata.xml',
                'acs_url': 'http://localhost:9000/saml/acs/',
                'certificate': SP_CERTIFICATE,
            },
        }
    ]
}

@attr.s
class User:
    username = attr.ib()
    email = attr.ib()


users = {user.username: user for user in [
    User('alex', 'alex@example.com'),
    User('jordan', 'jordan@example.com'),
]}


class ExampleIdentityProvider(IdentityProvider):

    def login_required(self):
        if not self.is_user_logged_in():
            redirect_url = self.request.route_url('login_view', _query={"next": self.request.url})
            raise HTTPFound(redirect_url)

    def is_user_logged_in(self):
        return 'user' in self.request.session and self.request.session['user'] in users

    def logout(self):
        del self.request.session['user']

    def get_current_user(self):
        return users[self.request.session['user']]


idp_cls = ExampleIdentityProvider


@view_defaults(route_name='login_view')
class LoginView:

    def __init__(self, request):
        self.request = request

    @view_config(request_method='GET')
    def get(self):
        options = ''.join(f'<option value="{user.username}">{user.email}</option>'
                            for user in users.values())

        next_url = self.request.params.get('next')

        html = f'''
            <html>
                <title>Login</title><p>Please log in to continue.</p>
                <body>
                <form action="" method="post">
                    <div><label>Select a user: <select name="user">{options}</select></label></div>
                    <input type="hidden" name="next" value="{next_url}">
                    <div><input type="submit" value="Login"></div>
                </form>
                </body>
            </html>
        '''

        return Response(html)

    @view_config(request_method='POST')
    def post(self):
        user = self.request.params['user']
        next = self.request.params['next']

        self.request.session['user'] = user
        logging.info("Logged user", user, "in")
        logging.info("Redirecting to", next)

        return HTTPFound(next)


if __name__ == '__main__':
    with Configurator(settings=settings) as config:
        config.add_route('login_view', '/login')

        session_factory = SignedCookieSessionFactory('itsaseekreet')
        config.set_session_factory(session_factory)
        config.commit()

        config.include('pyramid_saml2')
        config.configure_saml2_idp(idp_cls)

        config.scan()

        app = config.make_wsgi_app()

    server = make_server('0.0.0.0', PORT, app)
    server.serve_forever()
