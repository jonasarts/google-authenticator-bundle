Setting up the bundle
=====================

## Install the bundle

Execute this console command in your project:

``` bash
$ composer require jonasarts/google-authenticator-bundle
```

## Enable the bundle

Composer enables the bundle for you in config/bundles.php

Either create the `GoogleAuthenticator` class as you need or register it as service:

```yaml
#config/services.yaml
jonasarts\GoogleAuthenticatorBundle\Services\GoogleAuthenticator:
    public: true
```

You can now use the
`jonasarts\GoogleAuthenticatorBundle\Services\GoogleAuthenticator` class.

## That's it

Check out the docs for information on how to use the bundle! [Return to the index.](index.md)
