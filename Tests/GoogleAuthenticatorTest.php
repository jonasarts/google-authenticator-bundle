<?php

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

namespace jonasarts\GoogleAuthenticatorBundle\Tests;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

use jonasarts\GoogleAuthenticatorBundle\Services\GoogleAuthenticator;

class GoogleAuthenticatorTest extends WebTestCase
{
    /**
     * @var $googleAuthenticator GoogleAuthenticator
     */
    private $googleAuthenticator;

    protected function setUp()
    {
        $this->googleAuthenticator = new GoogleAuthenticator();
    }

    public function dataProvider()
    {
        // Secret, time, code
        return array(
            array('SECRET', '0', '200470'),
            array('SECRET', '1000', '115913'),
            array('SECRET', '100000', '550986'),
            array('SECRET', '10000000', '897390'),
        );
    }

    public function testInstance()
    {
        $ga = $this->googleAuthenticator;

        $this->assertInstanceOf('jonasarts\GoogleAuthenticatorBundle\Services\GoogleAuthenticator', $ga);
    }

    public function testBaseEncoder()
    {
        $ga = $this->googleAuthenticator;

        // RFC 4648 base32 alphabet; case-insensitive
        $base32 = $ga->getBase5Encoder('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
        $encoded = $base32->encode('encode this');
        // MVXGG33EMUQHI2DJOM======

        $this->assertEquals('MVXGG33EMUQHI2DJOM======', $encoded);
    }

    public function testBaseEncoderHex()
    {
        $ga = $this->googleAuthenticator;

        // RFC 4648 base32hex alphabet
        $base32hex = $ga->getBase5Encoder('0123456789ABCDEFGHIJKLMNOPQRSTUV');
        $encoded = $base32hex->encode('encode this');
        // CLN66RR4CKG78Q39EC======

        $this->assertEquals('CLN66RR4CKG78Q39EC======', $encoded);
    }

    public function testGenerateSecretLengthDefault()
    {
        $ga = $this->googleAuthenticator;

        $secret = $ga->generateSecret();
        $this->assertEquals(strlen($secret), 56);

        $plain = $ga->getBase5Encoder()->decode($secret);
        $this->assertEquals(strlen($plain), 32);
    }

    public function testGenerateSecretLength()
    {
        $ga = $this->googleAuthenticator;

        for ($i = 0; $i < 100; $i++) {
            $secret = $ga->generateSecret($i);
            $this->assertEquals(strlen($secret), (ceil($i/5)*8));

            $plain = $ga->getBase5Encoder()->decode($secret);
            $this->assertEquals(strlen($plain), $i);
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

        $this->assertEquals($urlParts['scheme'], 'https');
        $this->assertEquals($urlParts['host'], 'chart.googleapis.com');
        $this->assertEquals($urlParts['path'], '/chart');

        $expectedChl = 'otpauth://totp/' . $prefix . ':' . $accountname . '?secret=' . $secret . '&issuer=' . $issuer;

        $this->assertEquals(urldecode($queryStringArray['chl']), $expectedChl);

        // hotp
        $url = $ga->getQRCodeGoogleUrl($issuer, $accountname, $secret, $prefix, 'hotp', 100);

        $urlParts = parse_url($url);
        parse_str($urlParts['query'], $queryStringArray);

        $expectedChl = 'otpauth://hotp/' . $prefix . ':' . $accountname . '?secret=' . $secret . '&issuer=' . $issuer . '&counter=100';

        $this->assertEquals(urldecode($queryStringArray['chl']), $expectedChl);
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
