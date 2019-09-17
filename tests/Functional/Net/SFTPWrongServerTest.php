<?php

use phpseclib\Net\SFTP;
use PHPUnit\Framework\Error\Error;
use PHPUnit\Framework\TestCase;

class SFTPWrongServerTest extends TestCase
{
    public function testLoginToInvalidServer()
    {
        try {
          (new SFTP('dummy-server'))->login('username', 'password');
          static::fail('The connection to the non-existent server must not happen.');
        } catch (Error $e) {
          static::assertSame('Cannot connect to dummy-server:22. Error 0. php_network_getaddresses: getaddrinfo failed: Name or service not known', $e->getMessage());
        }
    }
}
