Using the bundle
================

The service class provides methods to generate and validate One-Time-Passwords (Tokens) as provided by the Google Authenticator project.

You can also use DI to retrieve the Service.

```php
    // get the service
    // use dependency injection or create the authenticator class
    $ga = new \jonasarts\Bundle\GoogleAuthenticatorBundle\Authenticator\GoogleAuthenticator();

    // generate a new secrect
    $secret = $ga->generateSecret();

    // generate the canonical otpauth key uri (the secret never leaves your server)
    $keyuri = $ga->getKeyURI('IssuerName', 'test@testhost', $secret);

    // render the key uri locally as a QR code, e.g. with jonasarts/phpqrcode-bundle
    echo '<img src="/qr/png?text='.$keyuri.'"><br>'; // this only works with phpqrcode-bundle installed!

    // get the current code
    $code = $ga->getCode($secret);

    echo "Checking Code '$code' and Secret '$secret':<br>";

    $result = $ga->checkCode($secret, $code, 1);    // discrepancy 1 = +/- 30 sec time tolerance
    if ($result) {
        echo 'Code ok';
    } else {
        echo 'Code failed';
    }
```

Replay-safe verification
------------------------

`checkCode()` returns a bool. For replay defense, use `verifyCode()` instead: it
returns the matched absolute time-slice (`floor(unixtime / 30)`) or `null` if no
code in the drift window matches. The bundle stays stateless — the caller stores
the last accepted slice and passes it back as `$notBeforeSlice`, so a code can
never be redeemed twice.

```php
    // $lastSlice is the last accepted slice for this user, loaded from your store
    // (null on first use). Only strictly-greater slices are accepted.
    $slice = $ga->verifyCode($secret, $code, 1, $lastSlice);
    if (null !== $slice) {
        // accept the login, then persist $slice as the new replay floor
        $user->setLastTotpSlice($slice);
        echo 'Code ok';
    } else {
        echo 'Code failed or already used';
    }
```

[Return to the index.](index.md)
