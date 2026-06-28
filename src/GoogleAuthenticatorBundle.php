<?php

declare(strict_types=1);

namespace jonasarts\Bundle\GoogleAuthenticatorBundle;

use Override;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

class GoogleAuthenticatorBundle extends AbstractBundle
{
    #[Override]
    public function getPath(): string
    {
        // Bundle class lives in src/, configuration lives in the bundle root.
        return \dirname(__DIR__);
    }

    /**
     * @param array<string, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import($this->getPath().'/config/services.yaml');
    }
}
