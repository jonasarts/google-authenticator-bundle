# Modernization Plan — jonasarts/google-authenticator-bundle

> Owner decision 2026-06-27. Target SF8.1/PHP8.4. Status: PLAN — standalone ausführbar.

## Decision

MUST-HAVE → **KEEP & IMPROVE**. Das Bundle wird enterprise-ready gemacht (analog registry2): Security-Fixes zuerst, danach Struktur-/Tooling-Modernisierung und vollständige Tests. Die öffentliche Bundle-API und die Symfony-DI-Integration (autowire-barer Service `…\Authenticator\GoogleAuthenticator`) bleiben stabil.

## Goals

- Zeitkonstante, RFC-konforme TOTP/HOTP-Implementierung ohne eigene Krypto-Risiken.
- SF8.1 / PHP8.4-Kompatibilität mit explizit deklarierten Dependencies.
- PSR-4 durchgängig, keine `require_once`/Global-Namespace-Klassen mehr.
- Korrekte, lauffähige Doku.
- Reproduzierbare Tests (RFC-Testvektoren) + CI.

## Security fixes (priorisiert, mit Datei-/Methodenbezug)

1. **[P0] Timing-sicherer Code-Vergleich** — `lib/GoogleAuthenticator.php::checkCode()` (Zeile ~223) vergleicht aktuell mit `==`. Umstellen auf `hash_equals($this->getCode($secret, $time + $i), $code)`. Damit kein Timing-Leak im MFA-Verify-Pfad.
2. **[P0] Sichere Secret-Generierung** — `generateSecret()` (Zeile ~53) erzeugt Bytes über eine `random_bytes(1)`-Schleife mit `% 127`-Mapping auf druckbares ASCII → Modulo-Bias und reduzierter Zeichenraum/Entropie. Ersetzen durch direktes `random_bytes($n)` und anschließendes Base32-Encoding des Roh-Outputs (Default 20 Bytes = 160 bit gemäß RFC 4226 §4). Kein Zwischenschritt über druckbare Zeichen.
3. **[P1] Toter Google-Charts-QR-Endpoint entfernen** — `getQRCodeGoogleUrl()` (Zeile ~203) zeigt auf das seit 2024 abgeschaltete `chart.googleapis.com`. Entfernen bzw. deprecaten. Ersatz: `getKeyURI()` (otpauth-URI) ist die kanonische Rückgabe; QR-Rendering an lokale Lib `endroid/qr-code` delegieren (kein externer Call, keine Secret-Leakage an Dritte). Optionaler `getQRCodeDataUri()`-Helfer auf Basis von `endroid/qr-code`.
4. **[P1] Doku-Methodennamen korrigieren** — `docs/02-basic-usage.md` ruft nicht-existente `verifyCode()` und `getKeyUri()` auf. Korrigieren auf reale Methoden `checkCode()` und `getKeyURI()`. Google-Charts-Beispiel durch otpauth-URI / `endroid`-Beispiel ersetzen.

## Crypto strategy (otphp-Delegation vs. Eigen-Krypto)

**Empfehlung (Best Practice): Krypto-Kern intern an `spomky-labs/otphp` delegieren.** Die Bundle-Klasse `…\Authenticator\GoogleAuthenticator` bleibt als Fassade mit unveränderter API (`generateSecret`, `getCode`, `checkCode`, `getKeyURI`), implementiert die Methoden aber via `OTPHP\TOTP`/`OTPHP\HOTP`. Vorteile: `hash_equals` und korrekte Secret-Generierung kommen out-of-the-box, RFC-konform und gepflegt; eigener `lib/Base2n.php` + `lib/GoogleAuthenticator.php` entfallen ersatzlos. Damit verschwinden die obigen P0-Risiken strukturell statt sie weiterzupflegen.

**Falls der Owner die Eigen-Krypto behalten will:** zwingend
- die Security-Fixes 1–2 umsetzen,
- vollständige **RFC-6238/4226-Testvektoren** (Appendix-B/D) als Tests hinterlegen,
- `lib/Base2n.php` als vendored Lib gegen `paragonie/constant_time_encoding` (Base32) tauschen.

Owner-Entscheidung offen — Plan bleibt in beiden Varianten ausführbar; Work-Items unten gelten für beide.

## Work items

- [ ] **PSR-4 heben:** `lib/GoogleAuthenticator.php` + `lib/Base2n.php` aus Global-Namespace/`require_once` lösen. Bei otphp-Delegation ersatzlos entfernen; sonst nach `src/` unter Namespace `jonasarts\Bundle\GoogleAuthenticatorBundle\…` verschieben. `require_once` in `src/Authenticator/GoogleAuthenticator.php` (Zeile ~16) entfernen.
- [ ] **composer.json:** explizite Deps deklarieren — `symfony/framework-bundle: ^8.0`, `symfony/dependency-injection: ^8.0`, `symfony/config: ^8.0`, `symfony/http-kernel: ^8.0`; bei Delegation `spomky-labs/otphp: ^11`; QR optional `endroid/qr-code` (suggest/require-dev). `require-dev`: `symfony/test-pack`/`phpunit/phpunit: ^11|^12`. `autoload-dev` PSR-4 auf das real existierende `Tests/`-Verzeichnis korrigieren (aktuell auf `tests/`).
- [ ] **Extension → AbstractBundle:** `GoogleAuthenticatorBundle` auf `Symfony\Component\HttpKernel\Bundle\AbstractBundle` umstellen, Service-Registrierung via `loadExtension()`/`configure()`. `src/DependencyInjection/GoogleAuthenticatorExtension.php` (nutzt das in SF8 zu migrierende `Extension`) entfernen oder anpassen. `services.yaml` beibehalten/migrieren, autowire+autoconfigure aktiv.
- [ ] **Doku-Fix:** `docs/02-basic-usage.md` Methodennamen + QR-Beispiel korrigieren; `README.md` Google-Code-Verweise entfernen; `docs/changes.md` Eintrag V8.0.0 anlegen.
- [ ] **Security-Fixes 1–4** aus obigem Abschnitt einbauen.

## Testing

- [ ] **RFC-Testvektoren:** RFC 6238 Appendix B (TOTP, SHA1) und RFC 4226 Appendix D (HOTP) als Data-Provider — bekannte Secret/Counter/Time → erwarteter Code.
- [ ] **Base32-Roundtrip:** encode→decode-Identität über Zufalls- und Grenzfälle (leerer String, Länge nicht durch 5 teilbar, Padding).
- [ ] **Discrepancy-Fenster:** `checkCode()` akzeptiert Code bei `t-discrepancy … t+discrepancy`, lehnt außerhalb ab; Default `discrepancy=1`.
- [ ] **Konstanzzeit:** Test, der sicherstellt, dass der Vergleich über `hash_equals` läuft (z. B. via gleicher Länge / Mutationstest / statischer Check), kein `==`.
- [ ] **Bestehende Tests modernisieren:** `Tests/GoogleAuthenticatorTest.php` von `WebTestCase` auf `TestCase` umstellen (kein Kernel nötig); `@dataProvider`-Annotation → `#[DataProvider]`-Attribut (PHPUnit 12).
- [ ] **Tooling:** `phpunit.xml` hinzufügen; CI-Pipeline (GitHub Actions) Matrix PHP 8.4 + SF8.1, `composer validate`, optional PHPStan.

## Definition of Done

- Alle P0/P1-Security-Punkte umgesetzt und durch Tests abgedeckt.
- Bundle installiert und autowired sauber unter SF8.1/PHP8.4; `composer validate` grün.
- Keine Global-Namespace-Klassen / `require_once` mehr; PSR-4 vollständig.
- RFC-Testvektoren grün; CI grün auf PHP 8.4 / SF8.1.
- Doku stimmt mit realer API überein; tote externe Endpoints entfernt.
- `docs/changes.md` enthält V8.0.0 mit Security-/BC-Hinweisen.

## Out of scope

- Vollständige Symfony-Security-/2FA-Workflow-Integration (Login-Flow, Two-Factor-Token, User-Entity-Trait) — dafür bleibt `scheb/2fa-bundle` die Referenz; dieses Bundle bleibt reiner TOTP/HOTP-Service.
- HOTP-Counter-Persistenz / Replay-Schutz (App-Verantwortung, nicht Bundle-Scope).
- UI/Templates für QR-Anzeige.
