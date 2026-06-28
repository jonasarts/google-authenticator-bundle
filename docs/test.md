Testing the bundle
==================

This bundle ships a real test suite plus the usual static-analysis and
code-style tooling. All commands are exposed as Composer scripts, mirroring the
other jonasarts bundles.

## Requirements

- PHP 8.4+
- Composer

No external services are needed — the suite is pure unit tests.

## Install the dev dependencies

From the bundle root:

```bash
composer install
```

This pulls in PHPUnit, PHPStan, Rector and PHP-CS-Fixer (see `require-dev`).

## Composer scripts

| Command | What it runs |
|---------|--------------|
| `composer test` | PHPUnit – **unit** suite (default suite) |
| `composer phpstan` | Static analysis (`phpstan.dist.neon`) |
| `composer cs-check` | PHP-CS-Fixer dry-run (report only) |
| `composer cs` | PHP-CS-Fixer – apply fixes |
| `composer rector-check` | Rector dry-run (report only) |
| `composer rector` | Rector – apply changes |

A full local check before tagging:

```bash
composer cs-check
composer rector-check
composer phpstan
composer test
```

## Test suite

The suite is defined in `phpunit.dist.xml`.

### unit — `tests/`

`GoogleAuthenticatorTest` exercises the TOTP/HOTP core against the official
specification:

- **RFC 6238 (TOTP)** and **RFC 4226 (HOTP)** test vectors.
- Base32 encode/decode round-trip (the `Encoder\Base2n` implementation).
- The discrepancy window (`checkCode()` accepting adjacent time steps).
- The constant-time comparison guard (`hash_equals()`), secret generation
  (`random_bytes()`-based, RFC-recommended length) and the base32 validation of
  supplied secrets.

Run the suite:

```bash
composer test
# or
vendor/bin/phpunit --testsuite unit
```

## Running a single test

```bash
vendor/bin/phpunit --testsuite unit --filter testCheckCode
```

## Coverage

Coverage needs Xdebug or PCOV. With one of them enabled:

```bash
XDEBUG_MODE=coverage vendor/bin/phpunit --testsuite unit --coverage-text
```

The covered sources are restricted to `src/` (see the `<source>` block in
`phpunit.dist.xml`).

## Continuous integration

`.github/workflows/ci.yml` runs the whole chain on a PHP 8.4 matrix:
`composer test`, PHPStan, `composer rector-check` and `composer cs-check`. A
green pipeline is the release gate.

[Return to the index.](index.md)
