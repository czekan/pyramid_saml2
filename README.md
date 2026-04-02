# pyramid-saml2

[![Tests](https://github.com/czekan/pyramid_saml2/actions/workflows/tests.yml/badge.svg)](https://github.com/czekan/pyramid_saml2/actions/workflows/tests.yml)

A Pyramid extension for creating SAML 2.0 Identity Providers.

## Requirements

- Python 3.6+
- Pyramid
- Additional dependencies installed automatically: `signxml`, `lxml`, `pyopenssl`, `pyramid_jinja2`

## Installation

```bash
pip install -U git+https://github.com/czekan/pyramid_saml2.git
```

Or clone and install locally:

```bash
git clone https://github.com/czekan/pyramid_saml2.git
cd pyramid_saml2
pip install .
```

For development (editable install):

```bash
pip install -e .
```

## Quick Start

1. Include `pyramid_saml2` in your Pyramid application and configure the IdP:

```python
from pyramid.config import Configurator
from pyramid.session import SignedCookieSessionFactory
from pyramid_saml2.idp import IdentityProvider, SPHandler
from pyramid_saml2.utils import certificate_from_file, private_key_from_file

settings = {
    'SAML2_IDP': {
        'autosubmit': True,
        'certificate': certificate_from_file('idp-certificate.pem'),
        'private_key': private_key_from_file('idp-private-key.pem'),
    },
    'SAML2_SERVICE_PROVIDERS': [
        {
            'CLASS': 'myapp.MySPHandler',
            'OPTIONS': {
                'display_name': 'My Service Provider',
                'entity_id': 'http://sp.example.com/saml/metadata.xml',
                'acs_url': 'http://sp.example.com/saml/acs/',
                'certificate': certificate_from_file('sp-certificate.pem'),
            },
        }
    ]
}

with Configurator(settings=settings) as config:
    session_factory = SignedCookieSessionFactory('secret')
    config.set_session_factory(session_factory)
    config.commit()  # session factory must be committed before including pyramid_saml2

    config.include('pyramid_saml2')
    config.configure_saml2_idp(MyIdentityProvider)  # defined in step 2
    config.scan()
```

2. Subclass `IdentityProvider` to implement authentication logic:

```python
class MyIdentityProvider(IdentityProvider):

    def login_required(self):
        if not self.is_user_logged_in():
            raise HTTPFound(self.request.route_url('login'))

    def is_user_logged_in(self):
        return 'user' in self.request.session

    def logout(self):
        del self.request.session['user']

    def get_current_user(self):
        return self.request.session['user']
```

3. Optionally customize the `SPHandler` to include additional SAML attributes:

```python
class MySPHandler(SPHandler):
    def build_assertion(self, request, *args, **kwargs):
        return {
            **super().build_assertion(request, *args, **kwargs),
            'ATTRIBUTES': {
                'foo': 'bar',
            },
        }
```

## Exposed Routes

Once configured, the following SAML endpoints are available:

| Route | Path | Description |
|-------|------|-------------|
| `pyramid_saml2_idp_login_begin` | `/saml/login/` | Initiates SSO login |
| `pyramid_saml2_idp_login_process` | `/saml/login/process/` | Processes the login |
| `pyramid_saml2_idp_logout` | `/saml/logout/` | Handles logout |
| `pyramid_saml2_idp_metadata` | `/saml/metadata.xml` | IdP metadata endpoint |

## Configuration

### `SAML2_IDP` settings

| Key | Description |
|-----|-------------|
| `certificate` | IdP X.509 certificate |
| `private_key` | IdP private key for signing |
| `autosubmit` | Auto-submit the SAML response form (default: `False`) |

### `SAML2_SERVICE_PROVIDERS` list

Each entry requires:

| Key | Description |
|-----|-------------|
| `CLASS` | Dotted path to your `SPHandler` subclass |
| `OPTIONS.display_name` | Human-readable SP name |
| `OPTIONS.entity_id` | SP entity ID (usually its metadata URL) |
| `OPTIONS.acs_url` | SP Assertion Consumer Service URL |
| `OPTIONS.certificate` | SP X.509 certificate |

### Logging

Set the `PYRAMID_SAML2_LOG_LEVEL` environment variable to `debug`, `warning`, or `error` to control log verbosity.

## Example

A complete working example is available in [`examples/idp.py`](examples/idp.py).

## History

This is a fork of [mx-moth/flask-saml2](https://github.com/mx-moth/flask-saml2) ported to Pyramid, which is a heavily modified fork of [NoodleMarkets/dj-saml-idp](https://github.com/NoodleMarkets/dj-saml-idp), itself forked from [deforestg/dj-saml-idp](https://github.com/deforestg/dj-saml-idp), originally from [novapost/django-saml2-idp](https://github.com/novapost/django-saml2-idp).

## License

Distributed under the BSD License.
