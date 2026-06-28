# Umsetzungsplan — jonasarts/google-authenticator-bundle

> Abgeleitet aus [MODERNIZATION.md](MODERNIZATION.md). Owner-Entscheidung 2026-06-27.
> Krypto-Variante: **Eigen-Krypto behalten** (otphp-Delegation verworfen).
> Ziel: SF 8.0/8.1 / PHP 8.4, enterprise-ready, BC-stabile öffentliche API.
> Release-Ziel: **V8.0.0**.
>
> **Status 2026-06-28: alle Phasen umgesetzt (lokal phpunit grün).**
> Details der getroffenen Entscheidungen unten unter „Entscheidungen & Abweichungen".

## Leitplanken (galten für jede Phase)

- Öffentliche API der Fassade `…\Authenticator\GoogleAuthenticator` bleibt stabil:
  `generateSecret`, `getCode`, `checkCode`, `getKeyURI`, `setCodeLength`,
  `getBase5Encoder`, `isValidBase5`.
- Autowire-barer Service-Name `…\Authenticator\GoogleAuthenticator` bleibt erhalten.
- Jede Phase endet grün: `composer validate` + `vendor/bin/phpunit` ohne Fehler.

---

## Phase 0 — Grundgerüst & Sicherheitsnetz ✅

- [x] `composer.json` Deps: `php >=8.4`, `symfony/{config,dependency-injection,framework-bundle,http-kernel}: ^8.0`, `require-dev phpunit ^11|^12`.
- [x] `autoload-dev` PSR-4 `tests/` → `Tests/` korrigiert.
- [x] `phpunit.xml` angelegt (Testsuite `Tests/`, `failOnDeprecation`/`failOnWarning`).
- [x] Baseline lokal gelaufen (nur erwarteter PHPUnit-12-Annotation-Fehler).

## Phase 1 — P0-Security-Fixes ✅

- [x] **[P0]** `checkCode()`: `== $code` → `hash_equals(getCode(...), $code)`.
- [x] **[P0]** `generateSecret()`: Modulo-Bias-Schleife → direktes `random_bytes($n)` + Base32-Encode; Guard für `$n < 1`.

## Phase 2 — P1: tote Endpoints & Doku ✅

- [x] **[P1]** `getQRCodeGoogleUrl()` **deprecated** (`trigger_deprecation`), Body funktional erhalten — *statt entfernt* (BC).
- [x] **[P1]** Doku-Fixes: `docs/02-basic-usage.md` (`verifyCode`→`checkCode`, `getKeyUri`→`getKeyURI`), `README.md` toter `code.google.com`-Link aktualisiert.
- [x] `symfony/deprecation-contracts: ^3.0` als Runtime-Dep ergänzt.
- [ ] ~~`getQRCodeDataUri()` + `endroid/qr-code`~~ — **verworfen** (siehe Abweichungen).

## Phase 3 — Struktur: PSR-4 & Symfony-DI ✅

- [x] `Base2n` nach `src/Encoder/Base2n.php` namespaced (Verhalten identisch — volle BC).
- [x] Krypto-Kern aus `lib/` in `src/Authenticator/GoogleAuthenticator.php` gemergt; `require_once` entfernt; `lib/` gelöscht.
- [x] Bundle → `AbstractBundle` (`loadExtension()` + `import()`); `GoogleAuthenticatorExtension` entfernt; `services.yaml` mit `autowire`/`autoconfigure`.
- [ ] ~~`Base2n` → `paragonie/constant_time_encoding`~~ — **vertagt** (siehe Abweichungen).

## Phase 4 — Tests (RFC-Vektoren + Modernisierung) ✅

- [x] **RFC 6238 App. B** (TOTP SHA1, 8-stellig) + **RFC 4226 App. D** (HOTP, 6-stellig) als `#[DataProvider]` — unabhängig (Python) gegengerechnet.
- [x] Base32-Roundtrip-Edgecases (leer, 1/4/5/6 Byte, voller Byte-Bereich).
- [x] Discrepancy-Fenster (boundary-robust).
- [x] Konstanzzeit-Guard (Quelltext-Check auf `hash_equals`, kein `== $code`).
- [x] `WebTestCase` → `TestCase`; alle `@dataProvider` → `#[DataProvider]`; nicht-RFC-Altvektoren entfernt.

## Phase 5 — Tooling, CI & Release ✅

- [x] **CI** `.github/workflows/ci.yml`: Matrix PHP 8.4 (deps highest/lowest), `composer validate --strict` + `phpunit`; optionaler (nicht-blockierender) PHPStan-Job + `phpstan.neon` (Level 6).
- [x] `docs/changes.md` V8.0.0 mit Requirements, Security-, BC- und Struktur-Hinweisen.
- [x] `docs/01-install.md` Requirements PHP 8.4 / Symfony 8.0–8.1.

---

## Entscheidungen & Abweichungen vom Ausgangsplan

1. **Eigen-Krypto behalten** (otphp-Delegation verworfen) — Owner-Entscheidung.

2. **`generateSecret()`-Default 32 → 20 Byte.** Der MODERNIZATION-Plan nannte 20 Byte
   nur als zu prüfenden Wert. Phase-4-Daten zeigten: 20 Byte (= 160 bit, RFC-4226-Empfehlung)
   ist ein Vielfaches von 5 → strikt RFC-4648-konform und app-kompatibel. 32 Byte (kein
   Vielfaches von 5) erzeugte ein nicht-RFC-konformes letztes Base32-Zeichen
   (latenter App-Kompatibilitätsbug). Bestehende Secrets bleiben gültig; nur der
   Default-Output ändert sich (52 → 32 Zeichen).

3. **`getQRCodeGoogleUrl()` deprecated statt entfernt** — BC-schonend; entfällt in einer
   späteren Major. Kanonischer Ersatz: `getKeyURI()` + lokales QR-Rendering.

4. **QR-Helfer + `endroid/qr-code` verworfen.** Zunächst als `getQRCodeDataUri()` eingebaut,
   dann auf Nachfrage wieder entfernt: zieht `bacon/bacon-qr-code`, und QR-Rendering ist
   laut Plan *out of scope*. QR-Weg bleibt `getKeyURI()` + `jonasarts/phpqrcode-bundle`
   (als `suggest` deklariert).

5. **`Base2n` behalten & namespaced; paragonie-Tausch vertagt.** `Base2n` nutzt
   `rightPadFinalBits = FALSE` → nicht-RFC-4648 bei Secrets, deren Roh-Länge kein
   Vielfaches von 5 Byte ist. Ein paragonie-Tausch (striktes RFC 4648) wäre ein
   BC-Break für solche bestehenden Secrets. Da der HOTP/TOTP-Kern nachweislich
   RFC-korrekt ist und der neue Default (20 Byte) das Problem praktisch entschärft,
   bleibt der Tausch bewusst offen. Entscheidungsgrundlage ist in `docs/changes.md`
   und hier dokumentiert.

## Definition of Done — erfüllt

- [x] Alle P0/P1-Security-Punkte umgesetzt und durch Tests abgedeckt.
- [x] Keine Global-Namespace-Klassen / kein `require_once`; PSR-4 vollständig.
- [x] RFC-Testvektoren vorhanden und grün; CI-Pipeline auf PHP 8.4.
- [x] Doku stimmt mit realer API überein; toter externer Endpoint deprecated.
- [x] `docs/changes.md` enthält V8.0.0 mit Security-/BC-Hinweisen.
- [x] Bundle installiert/autowired unter SF 8.x / PHP 8.4; `composer validate` lokal grün.

## Offene/optionale Folgepunkte

- Entscheidung paragonie-Tausch (RFC-4648 strict, constant-time) — falls gewünscht,
  als eigener Major mit Secret-Migrationspfad.
- PHPStan-Level schrittweise anheben und Baseline pflegen.

## Out of scope (unverändert)

- Vollständige Symfony-Security-/2FA-Workflow-Integration → `scheb/2fa-bundle`.
- HOTP-Counter-Persistenz / Replay-Schutz (App-Verantwortung).
- UI/Templates für QR-Anzeige.
