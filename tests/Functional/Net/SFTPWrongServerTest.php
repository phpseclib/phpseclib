<?php

declare(strict_types=1);

namespace phpseclib4\Tests\Functional\Net;

use phpseclib4\Exception\UnableToConnectException;
use phpseclib4\Net\SFTP;
use PHPUnit\Framework\TestCase;

class SFTPWrongServerTest extends TestCase
{
    public function testLoginToInvalidServer(): void
    {
        try {
            (new SFTP('dummy-server'))->login('username', 'password');
            static::fail('The connection to the non-existent server must not succeed.');
        } catch (UnableToConnectException $e) {
            // getaddrinfo message seems not to return stable text
            static::assertSame(
                'Cannot connect to dummy-server:22. Error 0. php_network_getaddresses: getaddrinfo',
                substr($e->getMessage(), 0, 81)
            );
        }
    }
}
