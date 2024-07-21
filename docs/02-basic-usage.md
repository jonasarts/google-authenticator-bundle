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

    // generate a key uri (perfect to use with the jonasarts/phpqrcode-bundle and not to send the secret to Google)
    $keyuri = $ga->getKeyUri('IssuerName', 'test@testhost', $secret);
    echo '<img src="/qr/png?text='.$keyuri.'"><br>'; // this only works with phpqrcode-bundle installed!

    // generate a QR Code Url to display with the Google Charts API
    $url = $ga->getQRCodeGoogleUrl('IssuerName', 'test@testhost', $secret);
    echo '<img src="'.$url.'"><br>';

    // get the current code
    $code = $ga->getCode($secret);

    echo "Checking Code '$code' and Secret '$secret':<br>";

    $result = $ga->verifyCode($secret, $code, 1);    // 2 = 1 * 30 sec time tolerance -> 30 sec before and 30 sec after
    if ($result) {
        echo 'Code ok';
    } else {
        echo 'Code failed';
    }
```

[Return to the index.](index.md)
