import logging

from pyramid.response import Response
from pyramid.httpexceptions import HTTPMethodNotAllowed, HTTPFound
from pyramid.view import view_config, view_defaults

from pyramid_saml2.exceptions import CannotHandleAssertion

logger = logging.getLogger(__name__)


@view_config(route_name='pyramid_saml2_idp_login_begin', request_method='GET')
@view_config(route_name='pyramid_saml2_idp_login_begin', request_method='POST')
def login_begin(request):
    saml_request = request.params.get('SAMLRequest')
    if not saml_request:
        return "SAMLRequest is missing"
    request.session['SAMLRequest'] = saml_request
    request.session['RelayState'] = request.params.get('RelayState', '')
    return HTTPFound(request.route_url('pyramid_saml2_idp_login_process'))


@view_config(
    route_name='pyramid_saml2_idp_login_process',
    request_method='GET',
    renderer='pyramid_saml2:idp/templates/login.jinja2')
def login_process(request):
    idp = request.registry['saml2_idp_cls'](request)
    idp.login_required()

    if 'SAMLRequest' not in request.session:
        return "SAMLRequest is misssing"
    if 'RelayState' not in request.session:
        return "RelayState is missing"

    saml_request = request.session['SAMLRequest']
    relay_state = request.session['RelayState']

    for handler in idp.get_sp_handlers():
        try:
            request = handler.parse_authn_request(saml_request)
            response = handler.make_response(request)
            context = handler.get_response_context(request, response, relay_state)
        except (CannotHandleAssertion, ValueError):
            logger.exception("%s could not handle login request", handler)
            pass
        else:
            return {"idp": idp, **context}
    raise CannotHandleAssertion(
        "No Service Provider handlers could handle this SAML request")


@view_config(
    route_name='pyramid_saml2_idp_logout',
    request_method='GET',
    renderer='pyramid_saml2:idp/templates/logged_out.jinja2')
def logout(request):
    """
    Allows a non-SAML 2.0 URL to log out the user and
    returns a standard logged-out page. (Salesforce and others use this method,
    though it's technically not SAML 2.0).
    """
    idp = request.registry['saml2_idp_cls'](request)
    idp.login_required()
    idp.logout()

    for arg in ['RelayState', 'redirect_to']:
        if arg not in request.params:
            continue
        redirect_url = request.params[arg]
        if redirect_url and idp.is_valid_redirect(redirect_url):
            return HTTPFound(location=redirect_url)

    return {"idp": idp, **context}


@view_config(
    route_name='pyramid_saml2_idp_metadata',
    request_method='GET',
    renderer='pyramid_saml2:idp/templates/metadata.jinja2')
def metadata(request):
    """
    Replies with the XML Metadata IDPSSODescriptor.
    """
    idp = request.registry['saml2_idp_cls'](request)
    request.response.content_type = 'application/xml'
    return {"idp": idp, **idp.get_metadata_context()}


@view_config(
    name='user_not_authorized',
    context='pyramid_saml2.exceptions.UserNotAuthorized',
    renderer='pyramid_saml2:idp/templates/invalid_user.jinja2'
)
def user_not_authorized_exc_view(exception, request):
    logger.exception("User not authorized", exc_info=exception)
    return {}


@view_config(
    name='cannot_handle_assertion',
    context='pyramid_saml2.exceptions.CannotHandleAssertion',
)
def cannot_handle_assertion_exc_view(exception, request):
    logger.exception("Can not handle request", exc_info=exception)
    request.response.status_code = 400
    return {}
