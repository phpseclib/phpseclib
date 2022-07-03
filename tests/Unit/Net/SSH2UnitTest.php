<?php

/**
 * @author    Marc Scholten <marc@pedigital.de>
 * @copyright 2013 Marc Scholten
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Net;

use phpseclib3\Tests\PhpseclibTestCase;

class SSH2UnitTest extends PhpseclibTestCase
{
    public function formatLogDataProvider(): array
    {
        return [
            [
                ['hello world'],
                ['<--'],
                "<--\r\n00000000  68:65:6c:6c:6f:20:77:6f:72:6c:64                 hello world\r\n\r\n"
            ],
            [
                ['hello', 'world'],
                ['<--', '<--'],
                "<--\r\n00000000  68:65:6c:6c:6f                                   hello\r\n\r\n" .
                "<--\r\n00000000  77:6f:72:6c:64                                   world\r\n\r\n"
            ],
        ];
    }

    /**
     * @dataProvider formatLogDataProvider
     */
    public function testFormatLog(array $message_log, array $message_number_log, $expected): void
    {
        $ssh = $this->createSSHMock();

        $result = self::callFunc($ssh, 'format_log', [$message_log, $message_number_log]);
        $this->assertEquals($expected, $result);
    }

    public function testGenerateIdentifier(): void
    {
        $identifier = self::callFunc($this->createSSHMock(), 'generate_identifier');
        $this->assertStringStartsWith('SSH-2.0-phpseclib_3.0', $identifier);

        if (function_exists('sodium_crypto_sign_keypair')) {
            $this->assertStringContainsString('libsodium', $identifier);
        }

        if (extension_loaded('openssl')) {
            $this->assertStringContainsString('openssl', $identifier);
            $this->assertStringNotContainsString('mcrypt', $identifier);
        } elseif (extension_loaded('mcrypt')) {
            $this->assertStringNotContainsString('openssl', $identifier);
            $this->assertStringContainsString('mcrypt', $identifier);
        } else {
            $this->assertStringNotContainsString('openssl', $identifier);
            $this->assertStringNotContainsString('mcrypt', $identifier);
        }

        if (extension_loaded('gmp')) {
            $this->assertStringContainsString('gmp', $identifier);
            $this->assertStringNotContainsString('bcmath', $identifier);
        } elseif (extension_loaded('bcmath')) {
            $this->assertStringNotContainsString('gmp', $identifier);
            $this->assertStringContainsString('bcmath', $identifier);
        } else {
            $this->assertStringNotContainsString('gmp', $identifier);
            $this->assertStringNotContainsString('bcmath', $identifier);
        }
    }

    public function testGetExitStatusIfNotConnected(): void
    {
        $ssh = $this->createSSHMock();

        $this->assertFalse($ssh->getExitStatus());
    }

    public function testPTYIDefaultValue(): void
    {
        $ssh = $this->createSSHMock();
        $this->assertFalse($ssh->isPTYEnabled());
    }

    public function testEnablePTY(): void
    {
        $ssh = $this->createSSHMock();

        $ssh->enablePTY();
        $this->assertTrue($ssh->isPTYEnabled());

        $ssh->disablePTY();
        $this->assertFalse($ssh->isPTYEnabled());
    }

    public function testQuietModeDefaultValue(): void
    {
        $ssh = $this->createSSHMock();

        $this->assertFalse($ssh->isQuietModeEnabled());
    }

    public function testEnableQuietMode(): void
    {
        $ssh = $this->createSSHMock();

        $ssh->enableQuietMode();
        $this->assertTrue($ssh->isQuietModeEnabled());

        $ssh->disableQuietMode();
        $this->assertFalse($ssh->isQuietModeEnabled());
    }

    public function testGetConnectionByResourceId(): void
    {
        $ssh = new \phpseclib3\Net\SSH2('localhost');
        $this->assertSame($ssh, \phpseclib3\Net\SSH2::getConnectionByResourceId($ssh->getResourceId()));
    }

    public function testGetResourceId(): void
    {
        $ssh = new \phpseclib3\Net\SSH2('localhost');
        $this->assertSame('{' . spl_object_hash($ssh) . '}', $ssh->getResourceId());
    }

    /**
     */
    protected function createSSHMock(): \phpseclib3\Net\SSH2
    {
        return $this->getMockBuilder('phpseclib3\Net\SSH2')
            ->disableOriginalConstructor()
            ->setMethods(['__destruct'])
            ->getMock();
    }
}
