<?php

declare(strict_types=1);

namespace jonasarts\Bundle\GoogleAuthenticatorBundle;

class GoogleAuthenticatorBundle extends Bundle
{
    public function getPath(): string
    {
        return \dirname(__DIR__);
    }
}
