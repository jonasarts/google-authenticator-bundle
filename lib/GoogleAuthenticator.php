<?php

/*
 * This file is part of the GoogleAuthenticator bundle package.
 *
 * (c) Jonas Hauser <symfony@jonasarts.com>
 *
 * This file is based on Christian Stockers GoogleAuthenticator:
 * https://github.com/chregu/GoogleAuthenticator.php/blob/master/lib/GoogleAuthenticator.php
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

require_once __DIR__ . "/Base2n.php";

class GoogleAuthenticator
{
    private $code_length = 6;

    /**
     * 
     * @param string $bytes
     * @param integer $start
     * @return integer
     */
    private function hashToInt($bytes, $start)
    {
        $input = substr($bytes, $start, strlen($bytes) - $start);

        //$value = unpack('N', $input);
        $value = unpack('N', substr($input, 0, 4));
        
        return $value[1];
    }
    
    /**
     * Constructor
     */
    public function __construct()
    {

    }

    /**
     * 
     * @param integer $baseLength
     * @return string
     */
    public function generateSecret($baseLength = 32)
    {
        $pass = array();
        $loop = 0;

        while ($loop < $baseLength) {
            $bytes = random_bytes(1);

            $hex = bin2hex($bytes);
            $val = hexdec($hex);
            $index = $val % 127;
            $char = chr($index);

            if (preg_match('/[\x21-\x7e]/', $char)) {
                $pass[] = $char;

                $loop++;
            }
        }

        $secret = implode($pass);

        $base5 = $this->getBase5Encoder();

        return $base5->encode($secret); // this is 2x the $baseLength
    }

    /**
     *
     * @param int $length Must at least be > 5 !
     * @return GoogleAuthenticator
     */
    public function setCodeLength($length)
    {
        if ($length < 6) {
            $length = 6;
        }

        $this->code_length = $length;

        return $this;
    }

    /**
     * 
     * @param string $chars
     * @return Base2n
     */
    public function getBase5Encoder($chars = null)
    {
        if (is_null($chars)) {
            // 32 chars
            //$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // old - v1.0.1
            $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // new - v2.0.0
        }

        return new \Base2n(5, $chars, FALSE, FALSE, FALSE); // not case sensitive, no pad last char, no padding at the end
    }

    /**
     * @param string $secret
     */
    public function isValidBase5($secret)
    {
        //return preg_match('/[A-Z2-7]/', $secret);
        return preg_match('/[A-Z2-9]/', $secret); // new - v2.0.0
    }
    
    /**
     * 
     * @param string $secret A Base5 encoded secret string
     * @param integer $time  A unix timestamp
     * @return string
     */
    public function getCode($secret, $time = null)
    {
        if ($time === null) {
            $time = floor(time() / 30);
        }

        // decode
        $base5 = $this->getBase5Encoder();
        $secret = $base5->decode($secret);
        
        // time to binary
        $time = pack('N', $time);
        $time = str_pad($time, 8, chr(0), STR_PAD_LEFT);
        
        // hash with user secret
        $hash = hash_hmac('SHA1',$time, $secret, true);

        // get offset
        $offset = ord(substr($hash, -1));
        $offset = $offset & 0xF;
        
        // binary to integer
        $value = $this->hashToInt($hash, $offset);
        $value = $value & 0x7FFFFFFF;

        // get modulo
        $pin_modulo = pow(10, $this->code_length);

        return str_pad($value % $pin_modulo, $this->code_length, '0', STR_PAD_LEFT);
    }
    
    /**
     * 
     * @param string  $issuer      A issuer identifier string
     * @param string  $accountname A user identifier, best to user email-address notation
     * @param string  $secret      A Base5 encoded secret string
     * @param string  $prefix      Optional prefix
     * @param string  $type        Optional type; totp/hotp
     * @param integer $counter     Optional initial counter value, required for hotp type
     * @return string
     */
    public function getKeyURI($issuer, $accountname, $secret, $prefix = '', $type = 'totp', $counter = 0)
    {
        // https://code.google.com/p/google-authenticator/wiki/KeyUriFormat
        // https://github.com/google/google-authenticator/wiki/Key-Uri-Format

        if (!$this->isValidBase5($secret)) {
            throw new \Exception('secret is not a valid base5 encoded string');
        }

        if (trim($prefix) != '') {
            $uri = sprintf('otpauth://%s/%s:%s?secret=%s&issuer=%s', $type, rawurlencode($prefix), rawurlencode($accountname), $secret, rawurlencode($issuer));
        } else {
            $uri = sprintf('otpauth://%s/%s?secret=%s&issuer=%s', $type, rawurlencode($accountname), $secret, rawurlencode($issuer));            
        }

        if ($type == 'hotp') {
            $uri = sprintf('%s&counter=%d', $uri, $counter);
        }

        return $uri;
    }

    /**
     * @param string  $issuer      A issuer identifier string
     * @param string  $accountname A user identifier, best to user email-address notation
     * @param string  $secret      A Base5 encoded secret string
     * @param string  $prefix      Optional prefix
     * @param string  $type        Optional type; totp/hotp
     * @param integer $counter     Optional initial counter value, required for hotp type
     * @return string
     */
    public function getQRCodeGoogleUrl($issuer, $accountname, $secret, $prefix = '', $type = 'totp', $counter = 0)
    {
        $qr_url = 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=';
        $otpauth = $this->getKeyURI($issuer, $accountname, $secret, $prefix, $type, $counter);

        return $qr_url . rawurlencode($otpauth); // encoee again to protect url-in-url
    }

    /**
     * 
     * @param string   $secret
     * @param string   $code
     * @param integer  $discrepancy
     * @return boolean
     */
    public function checkCode($secret, $code, $discrepancy = 1)
    {
        $time = floor(time() / 30); // 30 sec precision

        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            if ($this->getCode($secret, $time + $i) == $code) {
                return true;
            }
        }
        
        return false;
    }
}
