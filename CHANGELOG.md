# Changelog

## 0.2 (2026-04-02)

### Added
- Comprehensive test suite covering parsers, views, signing, XML templates, and configuration
- GitHub Actions CI workflow running tests on Python 3.9-3.13
- Test status badge on README

### Fixed
- Undefined `context` variable in logout view causing NameError at runtime
- Signature verification proceeding with `None` certificate on signed SAML requests
- Missing error handling for required XML elements in SAML request parsers
- Incorrect attribute reference (`self.name` instead of `self.__name__`) in `cached_property`
- `certificate_to_string()` called on `None` when IdP has no certificate configured
- Typo in error message ("misssing" -> "missing")
- Incorrect `logging.info()` calls in example

### Improved
- Complete README rewrite with quick start guide, configuration reference, and route documentation
- Installation instructions for GitHub-based install

## 0.1

- Initial release
- Pyramid SAML 2.0 Identity Provider support
- Ported from flask-saml2
