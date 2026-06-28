<?php

declare(strict_types=1);

/*
 * This file is part of the google-authenticator bundle package.
 *
 * (c) Jonas Hauser <symfony@jonasarts.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace jonasarts\Bundle\GoogleAuthenticatorBundle\Tests\Integration;

use jonasarts\Bundle\GoogleAuthenticatorBundle\Authenticator\GoogleAuthenticator;
use jonasarts\Bundle\GoogleAuthenticatorBundle\Tests\TestKernel;
use Override;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

/**
 * Integration test: boots the TestKernel to prove the SF8 AbstractBundle wiring
 * registers the GoogleAuthenticator service from the YAML service file and keeps
 * it fetchable from the (test) container. This also guards the runtime
 * dependency set: the bundle boots with only dependency-injection, http-kernel
 * and yaml at runtime.
 */
class GoogleAuthenticatorBundleTest extends KernelTestCase
{
    #[Override]
    protected static function getKernelClass(): string
    {
        return TestKernel::class;
    }

    #[Override]
    protected function tearDown(): void
    {
        restore_exception_handler();

        parent::tearDown();
    }

    public function testBundleBoots(): void
    {
        self::bootKernel();

        $this->assertTrue(self::getContainer()->has(GoogleAuthenticator::class));
    }

    public function testServiceIsInjectable(): void
    {
        self::bootKernel();

        $this->assertInstanceOf(
            GoogleAuthenticator::class,
            self::getContainer()->get(GoogleAuthenticator::class),
        );
    }
}
