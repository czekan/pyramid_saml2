from typing import Optional

from pyramid_saml2.types import XmlNode
from pyramid_saml2.utils import cached_property
from pyramid_saml2.xml_parser import XmlParser


class AuthnRequestParser(XmlParser):
    """Parses an incoming ``<AuthnRequest>``
    and provides shortcuts to access common attributes."""

    def is_signed(self) -> bool:
        """Is the ``<AuthnRequest>`` signed?"""
        return bool(self._xpath_xml_tree('/samlp:AuthnRequest/ds:Signature'))

    @cached_property
    def issuer(self) -> str:
        """The content of the ``<Issuer>`` element."""
        result = self._xpath_xml_tree('/samlp:AuthnRequest/saml:Issuer')
        if not result:
            raise ValueError("Missing required <Issuer> element in AuthnRequest")
        return result[0].text or ''

    @cached_property
    def request_id(self) -> str:
        """The ``<AuthnRequest>`` ID attribute."""
        result = self._xpath_xml_tree('/samlp:AuthnRequest/@ID')
        if not result:
            raise ValueError("Missing required ID attribute in AuthnRequest")
        return result[0]

    @cached_property
    def destination(self) -> str:
        """The ``<AuthnRequest>`` Destination attribute, if it has one."""
        try:
            return self._xpath_xml_tree('/samlp:AuthnRequest/@Destination')[0]
        except IndexError:
            return ''

    @cached_property
    def acs_url(self) -> str:
        """The AssertionConsumerServiceURL attribute."""
        result = self._xpath_xml_tree('/samlp:AuthnRequest/@AssertionConsumerServiceURL')
        if not result:
            raise ValueError("Missing required AssertionConsumerServiceURL attribute in AuthnRequest")
        return result[0]

    @cached_property
    def provider_name(self) -> str:
        """The ProviderName attribute, if it exists."""
        try:
            return self._xpath_xml_tree('/samlp:AuthnRequest/@ProviderName')[0]
        except IndexError:
            return ''

    @cached_property
    def version(self) -> str:
        """The Version attribute."""
        result = self._xpath_xml_tree('/samlp:AuthnRequest/@Version')
        if not result:
            raise ValueError("Missing required Version attribute in AuthnRequest")
        return result[0]

    @cached_property
    def issue_instant(self) -> str:
        """The IssueInstant attribute."""
        result = self._xpath_xml_tree('/samlp:AuthnRequest/@IssueInstant')
        if not result:
            raise ValueError("Missing required IssueInstant attribute in AuthnRequest")
        return result[0]

    @cached_property
    def protocol_binding(self) -> str:
        """The ProtocolBinding attribute."""
        result = self._xpath_xml_tree('/samlp:AuthnRequest/@ProtocolBinding')
        if not result:
            raise ValueError("Missing required ProtocolBinding attribute in AuthnRequest")
        return result[0]


class LogoutRequestParser(XmlParser):

    def is_signed(self):
        return bool(self._xpath_xml_tree('/samlp:LogoutRequest/ds:Signature'))

    @cached_property
    def issuer(self) -> str:
        result = self._xpath_xml_tree('/samlp:LogoutRequest/saml:Issuer')
        if not result:
            raise ValueError("Missing required <Issuer> element in LogoutRequest")
        return result[0].text or ''

    @cached_property
    def request_id(self) -> str:
        result = self._xpath_xml_tree('/samlp:LogoutRequest/@ID')
        if not result:
            raise ValueError("Missing required ID attribute in LogoutRequest")
        return result[0]

    @cached_property
    def destination(self) -> Optional[str]:
        try:
            return self._xpath_xml_tree('/samlp:LogoutRequest/@Destination')[0]
        except IndexError:
            return None

    @cached_property
    def version(self) -> str:
        result = self._xpath_xml_tree('/samlp:LogoutRequest/@Version')
        if not result:
            raise ValueError("Missing required Version attribute in LogoutRequest")
        return result[0]

    @cached_property
    def issue_instant(self) -> str:
        result = self._xpath_xml_tree('/samlp:LogoutRequest/@IssueInstant')
        if not result:
            raise ValueError("Missing required IssueInstant attribute in LogoutRequest")
        return result[0]

    @cached_property
    def nameid_el(self) -> XmlNode:
        result = self._xpath_xml_tree('/samlp:LogoutRequest/saml:NameID')
        if not result:
            raise ValueError("Missing required <NameID> element in LogoutRequest")
        return result[0]

    @cached_property
    def nameid(self) -> str:
        return self.nameid_el.text or ''

    @cached_property
    def nameid_format(self) -> str:
        result = self._xpath(self.nameid_el, '@Format')
        if not result:
            raise ValueError("Missing required Format attribute on <NameID> in LogoutRequest")
        return result[0]
