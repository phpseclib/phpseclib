<?php

namespace phpseclib3\Tests\Unit\Net;

use phpseclib3\Net\SSH2;
use phpseclib3\Tests\PhpseclibTestCase;

class SSH2ResourceIdTest extends PhpseclibTestCase
{
    public function testConstructorDoesNotTriggerDeprecations()
    {
        $deprecations = [];
        set_error_handler(function ($errno, $errstr) use (&$deprecations) {
            if (strpos($errstr, 'spl_object_hash') === false) {
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

    public function testResourceIdIdentifiesTheConnection()
    {
        $first = new SSH2('localhost');
        $second = new SSH2('localhost');

        $this->assertMatchesRegularExpression('/^\{[0-9a-f]{32}\}$/', $first->getResourceId());
        $this->assertNotSame($first->getResourceId(), $second->getResourceId());
        $this->assertSame($first, SSH2::getConnectionByResourceId($first->getResourceId()));
    }

    public function testResourceIdMatchesSplObjectHash()
    {
        if (PHP_VERSION_ID >= 80600) {
            $this->markTestSkipped('spl_object_hash() is deprecated as of PHP 8.6');
        }

        $ssh = new SSH2('localhost');

        $this->assertSame('{' . spl_object_hash($ssh) . '}', $ssh->getResourceId());
    }
}
