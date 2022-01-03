from typing import Generic, Iterable, Optional, Tuple, TypeVar

from pyramid.request import Request


from pyramid_saml2.exceptions import CannotHandleAssertion, UserNotAuthorized
from pyramid_saml2.signing import Digester, RsaSha1Signer, Sha1Digester, Signer
from pyramid_saml2.types import X509, PKey
from pyramid_saml2.utils import certificate_to_string, import_string

from .sphandler import SPHandler


class IdentityProvider:
    """
    Developers should subclass :class:`IdentityProvider`
    and provide methods to interoperate with their specific environment.
    All user interactions are performed through methods on this class.

    Every subclass should implement :meth:`is_user_logged_in`,
    :meth:`login_required`, :meth:`logout`, and :meth:`get_current_user`
    as a minimum.
    Other methods can be overridden as required.
    """
    #: The specific :class:`digest <~pyramid_saml2.signing.Digester>` method to
    #: use in this IdP when creating responses.
    #:
    #: See also: :meth:`get_idp_digester`,
    #: :meth:`~.sp.SPHandler.get_sp_digester`.
    idp_digester_class: Digester = Sha1Digester

    #: The specific :class:`signing <~pyramid_saml2.signing.Signer>` method to
    #: use in this IdP when creating responses.
    #:
    #: See also: :meth:`get_idp_signer`,
    #: :meth:`~.sp.SPHandler.get_sp_signer`.
    idp_signer_class: Signer = RsaSha1Signer

    # Configuration

    def __init__(self, request: Request):
        self.request = request

    def get_idp_config(self) -> dict:
        """
        Get the configuration for this IdP.
        Defaults to ``SAML2_IDP`` from :attr:`pyramid.registry.settings`.
        The configuration should be a dict like:

        .. code-block:: python

            {
                # Should the IdP automatically redirect the user back to the
                # Service Provider once authenticated.
                'autosubmit': True,
                # The X509 certificate and private key this IdP uses to
                # encrypt, validate, and sign payloads.
                'certificate': ...,
                'private_key': ...,
            }

        To load the ``certificate`` and ``private_key`` values, see

        - :func:`~.utils.certificate_from_string`
        - :func:`~.utils.certificate_from_file`
        - :func:`~.utils.private_key_from_string`
        - :func:`~.utils.private_key_from_file`
        """
        return self.request.registry.settings['SAML2_IDP']

    def should_sign_responses(self) -> bool:
        return self.get_idp_certificate() is not None \
            and self.get_idp_private_key() is not None

    def get_idp_entity_id(self) -> str:
        """The unique identifier for this Identity Provider.
        By default, this uses the metadata URL for this IdP.

        See :func:`get_metadata_url`.
        """
        return self.get_metadata_url()

    def get_idp_certificate(self) -> Optional[X509]:
        """Get the public certificate for this IdP.
        If this IdP does not sign its requests, returns None.
        """
        return self.get_idp_config().get('certificate')

    def get_idp_private_key(self) -> Optional[PKey]:
        """Get the private key for this IdP.
        If this IdP does not sign its requests, returns None.
        """
        return self.get_idp_config().get('private_key')

    def get_idp_autosubmit(self) -> bool:
        """Should the IdP autosubmit responses to the Service Provider?"""
        return self.get_idp_config().get('autosubmit', False)

    def get_idp_signer(self) -> Optional[Signer]:
        """Get the signing algorithm used by this IdP."""
        private_key = self.get_idp_private_key()
        if private_key is not None:
            return self.idp_signer_class(private_key)

    def get_idp_digester(self) -> Digester:
        """Get the method used to compute digests for the IdP."""
        return self.idp_digester_class()

    def get_service_providers(self) -> Iterable[Tuple[str, dict]]:
        """
        Get an iterable of service provider ``config`` dicts. ``config`` should
        be a dict specifying a SPHandler subclass and optionally any
        constructor arguments:

        .. code-block:: python

            >>> list(idp.get_service_providers())
            [{
                'CLASS': 'my_app.service_providers.MySPSPHandler',
                'OPTIONS': {
                    'acs_url': 'https://service.example.com/auth/acs/',
                },
            }]

        Defaults to ``self.request.registry.settings['SAML2_SERVICE_PROVIDERS']``.
        """
        return self.request.registry.settings['SAML2_SERVICE_PROVIDERS']

    def get_sso_url(self):
        """Get the URL for the Single Sign On endpoint for this IdP."""
        return self.request.route_url('pyramid_saml2_idp_login_begin')

    def get_slo_url(self):
        """Get the URL for the Single Log Out endpoint for this IdP."""
        return self.request.route_url('pyramid_saml2_idp_logout')

    def get_metadata_url(self):
        """Get the URL for the metadata XML document for this IdP."""
        return self.request.route_url('pyramid_saml2_idp_metadata')

    # Authentication

    def login_required(self):
        """Check if a user is currently logged in to this session, and
        abort with a redirect to the login page if not. It is
        suggested to use :meth:`is_user_logged_in`.
        """
        raise NotImplementedError

    def is_user_logged_in(self) -> bool:
        """Return True if a user is currently logged in.
        Subclasses should implement this method
        """
        raise NotImplementedError

    def logout(self):
        """Terminate the session for a logged in user.
        Subclasses should implement this method.
        """
        raise NotImplementedError

    # User

    def get_current_user(self):
        """Get the user that is currently logged in.
        """
        raise NotImplementedError

    def get_user_nameid(self, user, attribute: str):
        """Get the requested name or identifier from the user. ``attribute`` will
        be a ``urn:oasis:names:tc:SAML:2.0:nameid-format``-style urn.

        Subclasses can override this to allow more attributes to be extracted.
        By default, only email addresses are extracted using :meth:`get_user_email`.
        """
        if attribute == 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress':
            return self.get_user_email(user)

        raise NotImplementedError("Can't fetch attribute {} from user".format(attribute))

    def get_user_email(self, user):
        """Get the email address for a user."""
        return user.email

    # SPHandlers

    def get_sp_handlers(self) -> Iterable[SPHandler]:
        """Get the SPHandler for each service provider defined.
        """
        for config in self.get_service_providers():
            cls = import_string(config['CLASS'])
            options = config.get('OPTIONS', {})
            yield cls(self, **options)

    # Misc

    def get_metadata_context(self) -> dict:
        """Get any extra context for the metadata template.
        Suggested extra context variables include 'org' and 'contacts'.
        """
        return {
            'entity_id': self.get_idp_entity_id(),
            'certificate': certificate_to_string(self.get_idp_certificate()),
            'slo_url': self.get_slo_url(),
            'sso_url': self.get_sso_url(),
            'org': None,
            'contacts': [],
        }

    def is_valid_redirect(self, url: str) -> bool:
        """Check if a URL is a valid and safe URL to redirect to,
        according to any of the SPHandlers.
        Only used from the non-standard logout page,
        for non-compliant Service Providers such as Salesforce.
        """
        return any(
            handler.is_valid_redirect(url)
            for handler in self.get_sp_handlers()
        )
