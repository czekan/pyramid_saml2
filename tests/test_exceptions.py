from pyramid_saml2.exceptions import (
    CannotHandleAssertion,
    ImproperlyConfigured,
    MessageException,
    SAML2Exception,
    UserNotAuthorized,
)


class TestExceptions:
    def test_saml2_exception_is_exception(self):
        assert issubclass(SAML2Exception, Exception)

    def test_message_exception_str(self):
        exc = MessageException('test error')
        assert str(exc) == 'test error'
        assert exc.msg == 'test error'

    def test_message_exception_repr(self):
        exc = MessageException('test error')
        assert 'MessageException' in repr(exc)
        assert 'test error' in repr(exc)

    def test_cannot_handle_assertion(self):
        exc = CannotHandleAssertion('bad assertion')
        assert isinstance(exc, MessageException)
        assert isinstance(exc, SAML2Exception)
        assert str(exc) == 'bad assertion'

    def test_user_not_authorized(self):
        exc = UserNotAuthorized('forbidden')
        assert isinstance(exc, MessageException)
        assert str(exc) == 'forbidden'

    def test_improperly_configured(self):
        exc = ImproperlyConfigured('bad config')
        assert isinstance(exc, MessageException)
        assert str(exc) == 'bad config'
