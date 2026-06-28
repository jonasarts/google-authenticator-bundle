<?php

declare(strict_types=1);

/*
 * This file is part of the GoogleAuthenticator bundle package.
 *
 * (c) Jonas Hauser <symfony@jonasarts.com>
 *
 * This file is based on Michael Kliewes GoogleAuthenticatorTest:
 * https://github.com/PHPGangsta/GoogleAuthenticator/blob/master/tests/GoogleAuthenticatorTest.php
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace jonasarts\Bundle\GoogleAuthenticatorBundle\Tests;

use InvalidArgumentException;
use jonasarts\Bundle\GoogleAuthenticatorBundle\Authenticator\GoogleAuthenticator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class GoogleAuthenticatorTest extends TestCase
{
    private GoogleAuthenticator $googleAuthenticator;

    protected function setUp(): void
    {
        $this->googleAuthenticator = new GoogleAuthenticator();
    }

    // ---------------------------------------------------------------------
    // RFC test vectors (the authoritative correctness checks)
    //
    // All vectors use the shared RFC secret "12345678901234567890" (20 bytes).
    // 20 is a multiple of 5 bytes, so its Base32 encoding has no partial final
    // group — meaning the encoding is identical to strict RFC 4648 and these
    // vectors validate the HOTP/TOTP core independently of the Base32 padding
    // behaviour.
    // ---------------------------------------------------------------------

    /** Base32 of ASCII "12345678901234567890" (RFC 4648, no padding). */
    private const string RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    /**
     * RFC 4226 Appendix D — HOTP, SHA1, 6 digits.
     * counter => expected code.
     */
    public static function hotpRfc4226Provider(): array
    {
        return [
            [0, '755224'],
            [1, '287082'],
            [2, '359152'],
            [3, '969429'],
            [4, '338314'],
            [5, '254676'],
            [6, '287922'],
            [7, '162583'],
            [8, '399871'],
            [9, '520489'],
        ];
    }

    #[DataProvider('hotpRfc4226Provider')]
    public function testHotpRfc4226(int $counter, string $expected): void
    {
        // getCode() takes the moving factor (counter) directly; default 6 digits.
        $this->assertSame($expected, $this->googleAuthenticator->getCode(self::RFC_SECRET, $counter));
    }

    /**
     * RFC 6238 Appendix B — TOTP, SHA1, 8 digits.
     * The moving factor T = floor(unixTime / 30).
     * unixTime => expected code.
     */
    public static function totpRfc6238Provider(): array
    {
        return [
            [59,          '94287082'],
            [1111111109,  '07081804'],
            [1111111111,  '14050471'],
            [1234567890,  '89005924'],
            [2000000000,  '69279037'],
            [20000000000, '65353130'],
        ];
    }

    #[DataProvider('totpRfc6238Provider')]
    public function testTotpRfc6238(int $unixTime, string $expected): void
    {
        $ga = $this->googleAuthenticator;
        $ga->setCodeLength(8);

        $t = (int) floor($unixTime / 30);

        $this->assertSame($expected, $ga->getCode(self::RFC_SECRET, $t));
    }

    // ---------------------------------------------------------------------
    // checkCode behaviour
    // ---------------------------------------------------------------------

    public function testCheckCodeAcceptsAndRejects(): void
    {
        $ga = $this->googleAuthenticator;
        $secret = 'VerifyMe';

        $code = $ga->getCode($secret);
        $this->assertTrue($ga->checkCode($secret, $code));

        $this->assertFalse($ga->checkCode($secret, 'Invalid'));
    }

    /**
     * checkCode() must accept codes within [t-discrepancy, t+discrepancy]
     * and reject codes outside that window.
     */
    public function testCheckCodeDiscrepancyWindow(): void
    {
        $ga = $this->googleAuthenticator;
        $secret = self::RFC_SECRET;

        // The current code is always accepted (robust across a 30s boundary
        // because the default +/-1 window covers the step on either side).
        $this->assertTrue($ga->checkCode($secret, $ga->getCode($secret)));

        $now = (int) floor(time() / 30);

        // A code well outside the default +/-1 window must be rejected ...
        $this->assertFalse($ga->checkCode($secret, $ga->getCode($secret, $now + 5)));

        // ... but accepted once the discrepancy is widened to cover it.
        $this->assertTrue($ga->checkCode($secret, $ga->getCode($secret, $now + 5), 5));
    }

    /**
     * Guard against reintroducing a non-constant-time comparison: checkCode()
     * must verify via hash_equals() and never with a loose/strict equality on
     * the user-supplied code.
     */
    public function testCheckCodeUsesConstantTimeComparison(): void
    {
        $file = new ReflectionClass(GoogleAuthenticator::class)->getFileName();
        $source = file_get_contents($file);

        $this->assertStringContainsString('hash_equals(', $source);
        $this->assertStringNotContainsString('== $code', $source);
        $this->assertStringNotContainsString('=== $code', $source);
    }

    // ---------------------------------------------------------------------
    // Base32 (Base2n) encoding
    // ---------------------------------------------------------------------

    public function testBaseEncoder(): void
    {
        $ga = $this->googleAuthenticator;

        // RFC 4648 base32 alphabet; case-insensitive
        $base32 = $ga->getBase5Encoder('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
        $encoded = $base32->encode('encode this');

        $this->assertNotEquals('MVXGG33EMUQHI2DJOM======', $encoded);
        $this->assertEquals('MVXGG33EMUQHI2DJOD', $encoded);
    }

    public function testBaseEncoderHex(): void
    {
        $ga = $this->googleAuthenticator;

        // RFC 4648 base32hex alphabet
        $base32hex = $ga->getBase5Encoder('0123456789ABCDEFGHIJKLMNOPQRSTUV');
        $encoded = $base32hex->encode('encode this');

        $this->assertNotEquals('CLN66RR4CKG78Q39EC======', $encoded);
        $this->assertEquals('CLN66RR4CKG78Q39E3', $encoded);
    }

    public function testBaseEncoderForSecretWithoutPadding(): void
    {
        $ga = $this->googleAuthenticator;

        $base32 = $ga->getBase5Encoder();
        $secret = $base32->encode('SECRET');

        $this->assertEquals('KNCUGUSFKE', $secret);
    }

    /**
     * Encode/decode must round-trip losslessly, including edge cases: the empty
     * string, lengths not divisible by 5 bytes, and the full byte range.
     */
    public static function roundtripProvider(): array
    {
        return [
            'empty' => [''],
            '1 byte' => ["\x00"],
            '4 bytes' => ['ABCD'],
            '5 bytes' => ['ABCDE'],
            '6 bytes' => ['ABCDEF'],
            'text' => ['encode this'],
            'full range' => [implode('', array_map(chr(...), range(0, 255)))],
        ];
    }

    #[DataProvider('roundtripProvider')]
    public function testBase32Roundtrip(string $raw): void
    {
        $base32 = $this->googleAuthenticator->getBase5Encoder();

        $encoded = $base32->encode($raw);
        $decoded = $base32->decode($encoded);

        $this->assertSame($raw, $decoded);
    }

    // ---------------------------------------------------------------------
    // Secret generation
    // ---------------------------------------------------------------------

    public function testGenerateSecretLengthDefault(): void
    {
        $ga = $this->googleAuthenticator;

        $secret = $ga->generateSecret(); // default is 20 bytes of entropy (RFC 4226 §4)
        $this->assertEquals(32, strlen($secret)); // ceil(20 / 5 * 8) = 32

        $plain = $ga->getBase5Encoder()->decode($secret);
        $this->assertEquals(20, strlen((string) $plain));

        // the default length is a multiple of 5 bytes => strictly RFC 4648 base32
        $this->assertSame($secret, $ga->getBase5Encoder()->encode($plain));
    }

    public function testGenerateSecretLength(): void
    {
        $ga = $this->googleAuthenticator;

        for ($i = 0; $i < 100; ++$i) {
            $secret = $ga->generateSecret($i);
            $this->assertEquals(
                (int) ceil($i / 5 * 8),
                strlen($secret),
                sprintf('iteration %d', $i)
            );

            $plain = $ga->getBase5Encoder()->decode($secret);
            $this->assertEquals($i, strlen((string) $plain));
        }
    }

    public function testGenerateSecretIsUnique(): void
    {
        $ga = $this->googleAuthenticator;

        $a = $ga->generateSecret();
        $b = $ga->generateSecret();

        $this->assertNotSame($a, $b, 'two generated secrets must not be identical');
    }

    // ---------------------------------------------------------------------
    // Key URI
    // ---------------------------------------------------------------------

    public function testGetKeyUri(): void
    {
        $ga = $this->googleAuthenticator;

        $secret = 'Secret';
        $issuer = 'GoogleAuthenticator';
        $accountname = 'test@localhost';
        $prefix = 'Test';

        // totp with prefix
        $uri = $ga->getKeyURI($issuer, $accountname, $secret, $prefix);
        $this->assertSame(
            'otpauth://totp/'.$prefix.':'.rawurlencode($accountname).'?secret='.$secret.'&issuer='.$issuer,
            $uri
        );

        // hotp with counter
        $uri = $ga->getKeyURI($issuer, $accountname, $secret, $prefix, 'hotp', 100);
        $this->assertStringContainsString('otpauth://hotp/', $uri);
        $this->assertStringContainsString('&counter=100', $uri);
    }

    public function testGetKeyUriRejectsInvalidSecret(): void
    {
        $this->expectException(InvalidArgumentException::class);

        // '0' and '1' are not part of the RFC 4648 base32 alphabet
        $this->googleAuthenticator->getKeyURI('Issuer', 'account', '0110');
    }

    /**
     * isValidBase5() must validate the WHOLE string, not just contain one base32
     * character. counter-example => expected validity.
     */
    public static function isValidBase5Provider(): array
    {
        return [
            // valid (case-insensitive, unpadded base32)
            'rfc secret' => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', true],
            'uppercase' => ['ABCDEFGH', true],
            'lowercase' => ['verifyme', true],
            'digits 2-7' => ['ABC234567', true],
            // invalid
            'empty' => ['', false],
            'contains 0/1' => ['0110', false],
            'contains 8/9' => ['ABCD89', false],
            'punctuation' => ['hello!', false],
            'whitespace' => ['ABCD EFGH', false],
            'padding' => ['ABCDEF==', false],
            'mostly junk one valid char' => ['----A----', false],
        ];
    }

    #[DataProvider('isValidBase5Provider')]
    public function testIsValidBase5(string $secret, bool $expected): void
    {
        $this->assertSame($expected, $this->googleAuthenticator->isValidBase5($secret));
    }

    /**
     * The deprecated Google Charts helper still works but emits a deprecation.
     */
    #[IgnoreDeprecations]
    public function testGetQRCodeGoogleUrlIsStillFunctional(): void
    {
        $ga = $this->googleAuthenticator;

        $url = $ga->getQRCodeGoogleUrl('GoogleAuthenticator', 'test@localhost', 'Secret', 'Test');

        $urlParts = parse_url($url);
        $this->assertEquals('https', $urlParts['scheme']);
        $this->assertEquals('chart.googleapis.com', $urlParts['host']);
    }

    // ---------------------------------------------------------------------
    // Code length & misc
    // ---------------------------------------------------------------------

    public function testSetCodeLengthClampsAndIsFluent(): void
    {
        $ga = $this->googleAuthenticator;

        // fluent interface
        $this->assertSame($ga, $ga->setCodeLength(8));
        $this->assertSame(8, \strlen($ga->getCode(self::RFC_SECRET, 0)));

        // values below 6 are clamped to 6
        $ga->setCodeLength(3);
        $this->assertSame(6, \strlen($ga->getCode(self::RFC_SECRET, 0)));
    }

    public function testGeneratedSecretIsValidBase32(): void
    {
        $ga = $this->googleAuthenticator;

        for ($i = 0; $i < 20; ++$i) {
            $this->assertTrue($ga->isValidBase5($ga->generateSecret()));
        }
    }

    public function testGetCodeIsCaseInsensitiveForSecret(): void
    {
        $ga = $this->googleAuthenticator;

        // decode() is case-insensitive, so the same secret in either case must
        // produce the same one-time code.
        $this->assertSame(
            $ga->getCode(self::RFC_SECRET, 0),
            $ga->getCode(strtolower(self::RFC_SECRET), 0)
        );
    }

    public function testGetKeyUriWithoutPrefixIsTotpWithoutCounter(): void
    {
        $ga = $this->googleAuthenticator;

        $uri = $ga->getKeyURI('My Issuer', 'john doe@example.com', 'ABCDEF');

        $this->assertSame(
            'otpauth://totp/john%20doe%40example.com?secret=ABCDEF&issuer=My%20Issuer',
            $uri
        );
        $this->assertStringNotContainsString('counter=', $uri);
    }

    public function testCheckCodeRejectsEmptyAndWrongCode(): void
    {
        $ga = $this->googleAuthenticator;

        $this->assertFalse($ga->checkCode(self::RFC_SECRET, ''));
        $this->assertFalse($ga->checkCode(self::RFC_SECRET, 'not-a-code'));
    }
}
