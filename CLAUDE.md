# CLAUDE.md — rules for AI changes to this bundle

This is a jonasarts Symfony bundle. **`registry2-bundle` is the canonical
template**; keep this bundle aligned (checked by `registry2-bundle/tools/drift-lint.sh`).
This file and `CONTRIBUTING.md` are `export-ignore`d.

## Always

- After editing `composer.json`, run `composer normalize` and
  `composer validate --strict`. `composer normalize` owns field order/format.
- Keep `require` minimal and correct: `php` + the `symfony/*` components used at
  runtime, at `^7.0 || ^8.0`. `symfony/yaml` stays in `require` (the bundle imports
  `config/services.yaml`); composer-unused falsely flags it (ignored via
  `composer-unused.php`).
- Before claiming done, all gates must pass: `composer validate --strict`,
  `composer normalize --dry-run`, `composer cs-check`, `composer rector-check`,
  `composer phpstan`, `composer test`, `composer test-integration`,
  `composer audit`, plus `composer-require-checker check` and `composer-unused`.

## Never

- Never add a `version` field (Packagist uses the VCS tag).
- Never use `symfony/symfony`; depend on individual components.
- Never commit `composer.lock` (git-ignored; libraries don't ship a lock).
- Never rename the test dir away from lowercase `tests/`, or the config away from
  `phpunit.dist.xml`.
- Never delete user docs. Process docs (`MODERNIZATION.md`, `EXECUTION_PLAN.md`,
  `HANDOFF-*.md`, `docs/changes.md`) must not exist here.
- Never weaken a CI gate to make it pass; fix the cause.

## Conventions

- Test suites: `unit` (`tests/`) and `integration` (`tests/Integration/`, boots a
  test kernel). `composer test` = unit; `composer test-integration` = integration.
- The `GoogleAuthenticator` service is `public: true` so it stays fetchable /
  injectable and is not compiler-removed.
- Docs: `docs/index.md`, numbered topics (contiguous), `docs/test.md`. Changelog
  is the root `CHANGELOG.md` (Keep a Changelog + SemVer); top section is
  `Unreleased` until tagged.
- New dev/test/doc artifacts must be added to `.gitattributes` as `export-ignore`.

## Drift

When changing a shared convention, update the registry2 template first, then this
bundle, and confirm with `registry2-bundle/tools/drift-lint.sh`.
