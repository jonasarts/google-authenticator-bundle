# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [8.0.0] - 2026-06-28

### Added

- RFC 6238 (TOTP) and RFC 4226 (HOTP) test vectors, Base32 round-trip,
  discrepancy-window and constant-time guard tests; CI on PHP 8.4.

### Changed

- Requires PHP 8.4 and Symfony `^7.0 || ^8.0` (explicit dependencies on
  `symfony/framework-bundle`, `symfony/dependency-injection`, `symfony/config`,
  `symfony/http-kernel`).
- Source now passes PHPStan level 8 with no errors: added property and
  parameter/return type declarations on `Encoder\Base2n`, guarded the
  `unpack()`/`pack()` calls, and typed the bundle's `loadExtension()` config
  array. Base32 encode/decode output is unchanged (RFC vectors and round-trip
  tests prove it).
- PSR-4 throughout: the former global-namespace `lib/GoogleAuthenticator.php` and
  `lib/Base2n.php` were moved under `src/` (`…\Authenticator\GoogleAuthenticator`
  and `…\Encoder\Base2n`); all `require_once` calls removed.
- Bundle migrated to `AbstractBundle` (`loadExtension()`); the service stays
  autowired.
- `isValidBase5()` now returns a strict `bool` (was `bool|int`). Callers only
  ever used the result as a boolean, so the narrowing is behaviour-preserving.
- `getKeyURI()` now throws `\InvalidArgumentException` (was the generic
  `\Exception`) when the secret is not valid base32. `InvalidArgumentException`
  extends `Exception`, so existing `catch (\Exception)` blocks keep working.
- `getCode()` now builds the 8-byte counter with `pack('J')` instead of
  `pack('N')` + left padding. Byte-identical for moving factors below 2^32, but
  now also correct beyond it (removes the year-2106 / large-HOTP-counter overflow).
- **Default secret length changed from 32 to 20 bytes** (160 bit, the value
  recommended by RFC 4226 §4). 20 is a multiple of 5, so the Base32 output is now
  strictly RFC 4648 compliant and fully interoperable with authenticator apps.
  `generateSecret()` without arguments now returns a 32-character string (was 52).
  Previously stored secrets keep working unchanged. Custom lengths that are **not
  a multiple of 5 bytes** still produce a non-RFC-4648 final character and may not
  round-trip with third-party apps; prefer multiples of 5 (e.g. 20).

### Deprecated

- `getQRCodeGoogleUrl()` is deprecated via the native PHP 8.4 `#[\Deprecated]`
  attribute: it relies on the Google Charts API (`chart.googleapis.com`), which
  was shut down in 2024. Use `getKeyURI()` (the canonical otpauth URI) and render
  the QR code locally — e.g. with `jonasarts/phpqrcode-bundle`.

### Removed

- The `symfony/deprecation-contracts` dependency was removed; the deprecation is
  now emitted by the native attribute alone (no more double deprecation notice).

### Security

- `checkCode()` now uses `hash_equals()` for the code comparison (constant-time,
  removes a timing side-channel in the MFA verification path).
- `generateSecret()` now derives the secret directly from `random_bytes()`. The
  previous implementation mapped single random bytes onto printable ASCII via
  `% 127`, which introduced modulo bias and reduced entropy.
- `isValidBase5()` now validates the **whole** string against the base32 alphabet
  (anchored, case-insensitive). Previously it returned true if the input merely
  contained a single base32 character, so malformed secrets could pass the guard.

## [7.0.1]

- Fixed an issue with a PHP 8.4 nullable type declaration.

## [7.0.0]

- Requires PHP 8.2.

## [6.3.0]

- Requires PHP 8.1.
- Updated for the Symfony 6.3 branch.

## [6.0.4]

- Renamed files from `.yml` to `.yaml`.

## [6.0.3]

- Added `services.yaml` to register the authenticator service for dependency
  injection.

## [6.0.0]

- Update for PHP 8.* compatibility.
- Update for Symfony 5.* compatibility.
- Test release for Symfony 6.x (not ready for production).
