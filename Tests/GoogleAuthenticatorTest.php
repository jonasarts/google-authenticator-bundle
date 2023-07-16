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

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

use jonasarts\Bundle\GoogleAuthenticatorBundle\Authenticator\GoogleAuthenticator;

class GoogleAuthenticatorTest extends WebTestCase
{
    /**
     * @var $googleAuthenticator GoogleAuthenticator
     */
    private GoogleAuthenticator $googleAuthenticator;

    protected function setUp(): void
    {
        $this->googleAuthenticator = new GoogleAuthenticator();
    }

    public function dataProvider(): array
    {
        // Secret, time, code
        return array(
            array('SECRET', 0, '200470'),
            array('SECRET', 1000, '115913'),
            array('SECRET', 100000, '550986'),
            array('SECRET', 10000000, '897390'),
        );
    }

    public function testInstance()
    {
        $ga = $this->googleAuthenticator;

        $this->assertInstanceOf(\jonasarts\Bundle\GoogleAuthenticatorBundle\Authenticator\GoogleAuthenticator::class, $ga);
    }

    public function testBaseEncoder()
    {
        $ga = $this->googleAuthenticator;

        /**
         * Base2n defaults are:
         * $caseSensitive = TRUE, $rightPadFinalBits = FALSE, 
         * $padFinalGroup = FALSE, $padCharacter = '=')
         */

        // RFC 4648 base32 alphabet; case-insensitive
        $base32 = $ga->getBase5Encoder('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
        $encoded = $base32->encode('encode this');
        // MVXGG33EMUQHI2DJOM======
        // MVXGG33EMUQHI2DJOD

        $this->assertNotEquals('MVXGG33EMUQHI2DJOM======', $encoded);
        $this->assertEquals('MVXGG33EMUQHI2DJOD', $encoded);
    }

    public function testBaseEncoderHex()
    {
        $ga = $this->googleAuthenticator;

        // RFC 4648 base32hex alphabet
        $base32hex = $ga->getBase5Encoder('0123456789ABCDEFGHIJKLMNOPQRSTUV');
        $encoded = $base32hex->encode('encode this');
        // CLN66RR4CKG78Q39EC======
        // CLN66RR4CKG78Q39E3

        $this->assertNotEquals('CLN66RR4CKG78Q39EC======', $encoded);
        $this->assertEquals('CLN66RR4CKG78Q39E3', $encoded);
    }

    public function testBaseEncoderForSecretWithoutPadding()
    {
        $ga = $this->googleAuthenticator;

        $base32 = $ga->getBase5Encoder();

        $secret = $base32->encode('SECRET');
        // KNCUGUSFKQ======
        // KNCUGUSFKE

        $this->assertEquals('KNCUGUSFKE', $secret);
    }

    public function testBaseEncoderDecode()
    {
        $ga = $this->googleAuthenticator;

        $base32 = $ga->getBase5Encoder('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');

        $original = 'encode this';
        $encoded = $base32->encode($original);
        $decoded = $base32->decode($encoded);

        $this->assertEquals($original, $decoded);
    }

    public function testGenerateSecretLengthDefault()
    {
        $ga = $this->googleAuthenticator;

        $secret = $ga->generateSecret(); // default is 32
        //echo sprintf("\ngenerated default secret: %s (%d)\n", $secret, strlen($secret));
        $this->assertEquals(52, strlen($secret)); // 32 / 5 * 8 = 51.2 -> 52
        
        $plain = $ga->getBase5Encoder()->decode($secret);
        $this->assertEquals(32, strlen($plain));
    }

    public function testGenerateSecretLengthCustom()
    {
        $ga = $this->googleAuthenticator;

        // 24
        $secret24 = $ga->generateSecret(24);
        //echo sprintf("\ngenerated custom (24) secret: %s (%d)\n", $secret, strlen($secret));
        $this->assertEquals(39, strlen($secret24)); // 24 / 5 * 8 = ceil(38.4) -> 39
        
        $plain = $ga->getBase5Encoder()->decode($secret24);
        $this->assertEquals(24, strlen($plain));


        // 40 chars
        $secret40 = $ga->generateSecret(40);
        $this->assertEquals(64, strlen($secret40)); // 40 / 5 * 8 = 64

        // 48 chars
        $secret48 = $ga->generateSecret(48);
        $this->assertEquals(77, strlen($secret48)); // 48 / 5 * 8 = ceil(76.8) -> 77

        // 56 chars
        $secret56 = $ga->generateSecret(56);
        $this->assertEquals(90, strlen($secret56)); // 56 / 5 * 8 = ceil(89.6) -> 90
    }

    public function testGenerateSecretLength2()
    {
        $ga = $this->googleAuthenticator;

        $i = 32; // secret length to generate for google authenticator, base5 encoding will make it longer

        $secret = $ga->generateSecret($i);

        $this->assertEquals($i*1.625, strlen($secret));
    }

    public function testGenerateSecretLength()
    {
        $ga = $this->googleAuthenticator;

        for ($i = 0; $i < 100; $i++) {
            $secret = $ga->generateSecret($i);
            $this->assertEquals((ceil($i/5*8)), strlen($secret), sprintf('iteration %d : expected %f - actual %f', $i, (ceil($i/5*8)), strlen($secret)));

            $plain = $ga->getBase5Encoder()->decode($secret);
            $this->assertEquals($i, strlen($plain));
        }
    }

    /**
     * @dataProvider dataProvider
     */
    public function testGetCode($secret, $time, $code)
    {
        $generatedCode = $this->googleAuthenticator->getCode($secret, $time);

        $this->assertEquals($code, $generatedCode);
    }

    public function testGetQRCodeUrl()
    {
        $ga = $this->googleAuthenticator;

        $secret = 'Secret';
        $issuer = 'GoogleAuthenticator';
        $accountname = 'test@localhost';
        $prefix = 'Test';

        // totp
        $url = $ga->getQRCodeGoogleUrl($issuer, $accountname, $secret, $prefix);

        $urlParts = parse_url($url);
        parse_str($urlParts['query'], $queryStringArray);

        $this->assertEquals('https', $urlParts['scheme']);
        $this->assertEquals('chart.googleapis.com', $urlParts['host']);
        $this->assertEquals('/chart', $urlParts['path']);

        $expectedChl = 'otpauth://totp/' . $prefix . ':' . $accountname . '?secret=' . $secret . '&issuer=' . $issuer;

        $this->assertEquals($expectedChl, urldecode($queryStringArray['chl']));

        // hotp
        $url = $ga->getQRCodeGoogleUrl($issuer, $accountname, $secret, $prefix, 'hotp', 100);

        $urlParts = parse_url($url);
        parse_str($urlParts['query'], $queryStringArray);

        $expectedChl = 'otpauth://hotp/' . $prefix . ':' . $accountname . '?secret=' . $secret . '&issuer=' . $issuer . '&counter=100';

        $this->assertEquals($expectedChl, urldecode($queryStringArray['chl']));
    }

    public function testCheckCode()
    {
        $ga = $this->googleAuthenticator;

        $secret = 'VerifyMe';

        $code = $ga->getCode($secret);
        $result = $ga->checkCode($secret, $code);

        $this->assertEquals(true, $result);

        $code = 'Invalid';
        $result = $ga->checkCode($secret, $code);

        $this->assertEquals(false, $result);
    }
}
