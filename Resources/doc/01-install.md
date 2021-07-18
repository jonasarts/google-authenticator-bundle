Setting up the bundle
=====================

## Install the bundle

Execute this console command in your project:

``` bash
$ composer require jonasarts/google-authenticator-bundle
```

## Enable the bundle

Composer enables the bundle for you in config/bundles.php

Either create the `GoogleAuthenticator` as you need or register it as service
for dependency-injection:

```yaml
#config/services.yaml
jonasarts\Bundle\PHPQRCodeBundle\:
    resource: '../vendor/jonasarts/phpqrcode-bundle/*'
    exclude: '../vendor/jonasarts/phpqrcode-bundle/{DependencyInjection,lib,Tests}'
```

You can now use the
`jonasarts\Bundle\GoogleAuthenticatorBundle\Services\GoogleAuthenticator` class.

## That's it

Check out the docs for information on how to use the bundle! [Return to the index.](index.md)
