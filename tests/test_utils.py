from pathlib import Path

import pytest

from pyramid_saml2.utils import (
    cached_property,
    certificate_from_file,
    certificate_from_string,
    certificate_to_string,
    get_random_id,
    import_string,
    private_key_from_file,
    private_key_from_string,
    utcnow,
)


KEY_DIR = Path(__file__).parent / 'keys' / 'sample'


class TestCachedProperty:
    def test_caches_result(self):
        call_count = 0

        class Obj:
            @cached_property
            def value(self):
                nonlocal call_count
                call_count += 1
                return 42

        obj = Obj()
        assert obj.value == 42
        assert obj.value == 42
        assert call_count == 1

    def test_prevents_set(self):
        class Obj:
            @cached_property
            def value(self):
                return 42

        obj = Obj()
        _ = obj.value
        with pytest.raises(AttributeError, match="Can not set read-only attribute"):
            obj.value = 99

    def test_prevents_delete(self):
        class Obj:
            @cached_property
            def value(self):
                return 42

        obj = Obj()
        _ = obj.value
        with pytest.raises(AttributeError, match="Can not delete read-only attribute"):
            del obj.value

    def test_class_access_returns_descriptor(self):
        class Obj:
            @cached_property
            def value(self):
                return 42

        assert isinstance(Obj.value, cached_property)


class TestGetRandomId:
    def test_starts_with_underscore(self):
        assert get_random_id().startswith('_')

    def test_unique(self):
        ids = {get_random_id() for _ in range(100)}
        assert len(ids) == 100


class TestUtcnow:
    def test_has_timezone(self):
        now = utcnow()
        assert now.tzinfo is not None

    def test_returns_utc(self):
        now = utcnow()
        import datetime
        assert now.tzinfo == datetime.timezone.utc


class TestImportString:
    def test_imports_class(self):
        cls = import_string('pyramid_saml2.utils.cached_property')
        assert cls is cached_property

    def test_raises_for_missing(self):
        with pytest.raises(AttributeError):
            import_string('pyramid_saml2.utils.NonExistent')


class TestCertificateUtils:
    def test_load_certificate_from_file(self):
        cert = certificate_from_file(KEY_DIR / 'idp-certificate.pem')
        assert cert is not None

    def test_certificate_roundtrip(self):
        cert = certificate_from_file(KEY_DIR / 'idp-certificate.pem')
        cert_string = certificate_to_string(cert)
        assert len(cert_string) > 0
        assert '-----BEGIN' not in cert_string
        assert '\n' not in cert_string

    def test_load_private_key_from_file(self):
        key = private_key_from_file(KEY_DIR / 'idp-private-key.pem')
        assert key is not None

    def test_certificate_from_string(self):
        with open(KEY_DIR / 'idp-certificate.pem') as f:
            pem = f.read()
        cert = certificate_from_string(pem)
        assert cert is not None

    def test_private_key_from_string(self):
        with open(KEY_DIR / 'idp-private-key.pem') as f:
            pem = f.read()
        key = private_key_from_string(pem)
        assert key is not None
