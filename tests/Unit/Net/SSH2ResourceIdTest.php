<?php

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Net;

use phpseclib4\Net\SSH2;
use phpseclib4\Tests\PhpseclibTestCase;

class SSH2ResourceIdTest extends PhpseclibTestCase
{
    public function testConstructorDoesNotTriggerDeprecations(): void
    {
        $deprecations = [];
        set_error_handler(function (int $errno, string $errstr) use (&$deprecations): bool {
            if (!str_contains($errstr, 'spl_object_hash')) {
                return false;
            }
            $deprecations[] = $errstr;
            return true;
        }, E_DEPRECATED | E_USER_DEPRECATED);

        try {
            $ssh = new SSH2('localhost');
            $ssh->getResourceId();
        } finally {
            restore_error_handler();
        }

        $this->assertSame([], $deprecations);
    }

    public function testResourceIdIdentifiesTheConnection(): void
    {
        $first = new SSH2('localhost');
        $second = new SSH2('localhost');

        $this->assertMatchesRegularExpression('/^\{[0-9a-f]{32}\}$/', $first->getResourceId());
        $this->assertNotSame($first->getResourceId(), $second->getResourceId());
    }
}
