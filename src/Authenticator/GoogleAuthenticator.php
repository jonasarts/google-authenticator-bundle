<?php

declare(strict_types=1);

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

namespace jonasarts\Bundle\GoogleAuthenticatorBundle\Authenticator;

use Deprecated;
use InvalidArgumentException;
use jonasarts\Bundle\GoogleAuthenticatorBundle\Encoder\Base2n;
use RuntimeException;

/**
 * GoogleAuthenticator Service.
 *
 * Provides RFC 4226 (HOTP) / RFC 6238 (TOTP) one-time-password generation and
 * verification compatible with the Google Authenticator project.
 */
class GoogleAuthenticator
{
    private int $code_length = 6;

    private function hashToInt(string $bytes, int $start): int
    {
        $input = substr($bytes, $start, strlen($bytes) - $start);

        $value = unpack('N', substr($input, 0, 4));
        if (false === $value) {
            throw new RuntimeException('unable to unpack hash bytes');
        }

        return (int) $value[1];
    }

    /**
     * Generate a cryptographically secure, Base32-encoded secret.
     *
     * @param int $baseLength Number of raw random bytes to generate (entropy in bytes).
     *                        Default 20 bytes = 160 bit, the value recommended by
     *                        RFC 4226 §4. 20 is a multiple of 5, so the Base32
     *                        output has no partial final group and is strictly
     *                        RFC 4648 compliant (fully interoperable with
     *                        authenticator apps). The encoded result is
     *                        ceil($baseLength / 5 * 8) characters long.
     *
     *                            NOTE: lengths that are not a multiple of 5 bytes
     *                            produce a non-RFC-4648 final character and may not
     *                            round-trip correctly with third-party apps.
     *
     * @throws \Random\RandomException
     */
    public function generateSecret(int $baseLength = 20): string
    {
        if ($baseLength < 1) {
            return '';
        }

        // Directly use the CSPRNG output as secret material — no printable-char
        // detour and no modulo bias (previous % 127 mapping reduced entropy).
        $secret = random_bytes($baseLength);

        // Base32-encode the raw bytes; same output length as before (ceil(n/5*8)).
        return $this->getBase5Encoder()->encode($secret);
    }

    /**
     * @param int $length Must at least be > 5 !
     */
    public function setCodeLength(int $length): static
    {
        if ($length < 6) {
            $length = 6;
        }

        $this->code_length = $length;

        return $this;
    }

    public function getBase5Encoder(?string $chars = null): Base2n
    {
        if (null === $chars) {
            // RFC 4648 base32 alphabet; case-insensitive
            $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        }

        // not case sensitive, no pad last char, no padding at the end
        return new Base2n(5, $chars, false, false, false, '=');
    }

    public function isValidBase5(string $secret): bool
    {
        // The whole string must be RFC 4648 base32 (case-insensitive, unpadded);
        // decode() is case-insensitive, so lowercase secrets are accepted too.
        return 1 === preg_match('/^[A-Za-z2-7]+$/', $secret);
    }

    /**
     * @param string   $secret A Base5 encoded secret string
     * @param int|null $time   A unix timestamp
     */
    public function getCode(string $secret, ?int $time = null): string
    {
        if (null === $time) {
            $time = (int) floor(time() / 30);
        }

        // decode
        $base5 = $this->getBase5Encoder();
        // decode() only returns null in strict mode, which is never used here.
        $secret = $base5->decode($secret) ?? '';

        // 8-byte big-endian counter (RFC 4226). pack('J') covers the full 64-bit
        // range; for values below 2^32 it is byte-identical to the previous
        // pack('N') left-padded to 8 bytes, so existing codes are unaffected.
        $binaryTime = pack('J', $time);

        // hash with user secret
        $hash = hash_hmac('SHA1', $binaryTime, $secret, true);

        // get offset
        $offset = ord(substr($hash, -1));
        $offset &= 0xF;

        // binary to integer
        $value = $this->hashToInt($hash, $offset);
        $value &= 0x7FFFFFFF;

        // get modulo
        $pin_modulo = 10 ** $this->code_length;

        $result = $value % $pin_modulo;

        return str_pad((string) $result, $this->code_length, '0', \STR_PAD_LEFT);
    }

    /**
     * @param string $issuer      A issuer identifier string
     * @param string $accountname A user identifier, best to user email-address notation
     * @param string $secret      A base32 encoded secret string
     * @param string $prefix      Optional prefix
     * @param string $type        Optional type; totp/hotp
     * @param int    $counter     Optional initial counter value, required for hotp type
     *
     * @throws InvalidArgumentException when $secret is not a valid base32 string
     */
    public function getKeyURI(string $issuer, string $accountname, string $secret, string $prefix = '', string $type = 'totp', int $counter = 0): string
    {
        // https://github.com/google/google-authenticator/wiki/Key-Uri-Format

        if (!$this->isValidBase5($secret)) {
            throw new InvalidArgumentException('secret is not a valid base5 encoded string');
        }

        if ('' !== trim($prefix)) {
            $uri = sprintf('otpauth://%s/%s:%s?secret=%s&issuer=%s', $type, rawurlencode($prefix), rawurlencode($accountname), $secret, rawurlencode($issuer));
        } else {
            $uri = sprintf('otpauth://%s/%s?secret=%s&issuer=%s', $type, rawurlencode($accountname), $secret, rawurlencode($issuer));
        }

        if ('hotp' === $type) {
            $uri = sprintf('%s&counter=%d', $uri, $counter);
        }

        return $uri;
    }

    /**
     * @param string $issuer      A issuer identifier string
     * @param string $accountname A user identifier, best to user email-address notation
     * @param string $secret      A base32 encoded secret string
     * @param string $prefix      Optional prefix
     * @param string $type        Optional type; totp/hotp
     * @param int    $counter     Optional initial counter value, required for hotp type
     *
     * @throws InvalidArgumentException when $secret is not a valid base32 string
     */
    #[Deprecated(message: 'relies on the discontinued Google Charts API (chart.googleapis.com, shut down in 2024); use getKeyURI() (otpauth URI) and render the QR code locally instead', since: '8.0')]
    public function getQRCodeGoogleUrl(string $issuer, string $accountname, string $secret, string $prefix = '', string $type = 'totp', int $counter = 0): string
    {
        $qr_url = 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=';
        $otp_auth = $this->getKeyURI($issuer, $accountname, $secret, $prefix, $type, $counter);

        return $qr_url.rawurlencode($otp_auth); // encode again to protect url-in-url
    }

    /**
     * Verify a TOTP code; return the matched absolute time-slice (floor(time/30)),
     * or null if no code in the drift window matches.
     *
     * Enables replay defense in the CALLER: pass the last accepted slice as
     * $notBeforeSlice — only strictly-greater slices match, so a code cannot be
     * redeemed twice. The caller persists the returned slice. This class stores
     * nothing. Timing-safe (hash_equals).
     *
     * @param int|null $notBeforeSlice reject matches at or below this slice (replay floor)
     * @param int|null $atTime         unix timestamp to evaluate at (default now) — for tests
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1, ?int $notBeforeSlice = null, ?int $atTime = null): ?int
    {
        $current = (int) floor(($atTime ?? time()) / 30);

        for ($i = -$discrepancy; $i <= $discrepancy; ++$i) {
            $slice = $current + $i;

            if (null !== $notBeforeSlice && $slice <= $notBeforeSlice) {
                continue;
            }

            // timing-safe comparison; getCode() is the known value, $code is user input
            if (hash_equals($this->getCode($secret, $slice), $code)) {
                return $slice;
            }
        }

        return null;
    }

    public function checkCode(string $secret, string $code, int $discrepancy = 1): bool
    {
        return null !== $this->verifyCode($secret, $code, $discrepancy);
    }
}
