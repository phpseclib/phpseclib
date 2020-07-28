<?php

use phpseclib3\Net\SFTP;
use phpseclib3\Exception\UnableToConnectException;
use PHPUnit\Framework\TestCase;

class SFTPWrongServerTest extends TestCase
{
    public function testLoginToInvalidServer()
    {
        try {
            (new SFTP('dummy-server'))->login('username', 'password');
            static::fail('The connection to the non-existent server must not succeed.');
        } catch (UnableToConnectException $e) {
            // getaddrinfo message seems not to return stable text
            static::assertSame(
              'Cannot connect to dummy-server:22. Error 0. php_network_getaddresses: getaddrinfo failed:',
              substr($e->getMessage(),0,89)
            );
        }
    }
}
