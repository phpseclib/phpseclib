<?php

/**
 * @author    Marc Scholten <marc@pedigital.de>
 * @copyright 2013 Marc Scholten
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Net;

use phpseclib3\Exception\InsufficientSetupException;
use phpseclib3\Net\SSH2;
use phpseclib3\Tests\PhpseclibTestCase;

class SSH2UnitTest extends PhpseclibTestCase
{
    public function formatLogDataProvider(): array
    {
        return [
            [
                ['hello world'],
                ['<--'],
                "<--\r\n00000000  68:65:6c:6c:6f:20:77:6f:72:6c:64                 hello world\r\n\r\n",
            ],
            [
                ['hello', 'world'],
                ['<--', '<--'],
                "<--\r\n00000000  68:65:6c:6c:6f                                   hello\r\n\r\n" .
                "<--\r\n00000000  77:6f:72:6c:64                                   world\r\n\r\n",
            ],
        ];
    }

    /**
     * @dataProvider formatLogDataProvider
     * @requires PHPUnit < 10
     */
    public function testFormatLog(array $message_log, array $message_number_log, $expected): void
    {
        $ssh = $this->createSSHMock();

        $result = self::callFunc($ssh, 'format_log', [$message_log, $message_number_log]);
        $this->assertEquals($expected, $result);
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testGenerateIdentifier(): void
    {
        $identifier = self::callFunc($this->createSSHMock(), 'generate_identifier');
        $this->assertStringStartsWith('SSH-2.0-phpseclib_3.0', $identifier);

        if (function_exists('sodium_crypto_sign_keypair')) {
            $this->assertStringContainsString('libsodium', $identifier);
        }

        if (extension_loaded('openssl')) {
            $this->assertStringContainsString('openssl', $identifier);
        } else {
            $this->assertStringNotContainsString('openssl', $identifier);
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

    /**
     * @requires PHPUnit < 10
     */
    public function testGetExitStatusIfNotConnected(): void
    {
        $ssh = $this->createSSHMock();

        $this->assertFalse($ssh->getExitStatus());
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testPTYIDefaultValue(): void
    {
        $ssh = $this->createSSHMock();
        $this->assertFalse($ssh->isPTYEnabled());
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testEnablePTY(): void
    {
        $ssh = $this->createSSHMock();

        $ssh->enablePTY();
        $this->assertTrue($ssh->isPTYEnabled());

        $ssh->disablePTY();
        $this->assertFalse($ssh->isPTYEnabled());
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testQuietModeDefaultValue(): void
    {
        $ssh = $this->createSSHMock();

        $this->assertFalse($ssh->isQuietModeEnabled());
    }

    /**
     * @requires PHPUnit < 10
     */
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
        $ssh = new SSH2('localhost');
        $this->assertSame($ssh, SSH2::getConnectionByResourceId($ssh->getResourceId()));
    }

    public function testGetResourceId(): void
    {
        $ssh = new SSH2('localhost');
        $this->assertSame('{' . spl_object_hash($ssh) . '}', $ssh->getResourceId());
    }

    public function testReadUnauthenticated(): void
    {
        $this->expectException(InsufficientSetupException::class);
        $this->expectExceptionMessage('Operation disallowed prior to login()');

        $ssh = $this->createSSHMock();

        $ssh->read();
    }

    public function testWriteUnauthenticated(): void
    {
        $this->expectException(InsufficientSetupException::class);
        $this->expectExceptionMessage('Operation disallowed prior to login()');

        $ssh = $this->createSSHMock();

        $ssh->write('');
    }

    public function testWriteOpensShell(): void
    {
        $ssh = $this->getMockBuilder(SSH2::class)
            ->disableOriginalConstructor()
            ->setMethods(['__destruct', 'openShell', 'send_channel_packet'])
            ->getMock();
        $ssh->expects($this->once())
            ->method('openShell')
            ->willReturn(true);
        $ssh->expects($this->once())
            ->method('send_channel_packet')
            ->with(SSH2::CHANNEL_SHELL, 'hello');

        $ssh->write('hello');
    }

    public function testOpenShellWhenOpen(): void
    {
        $ssh = $this->getMockBuilder(SSH2::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['__destruct', 'isShellOpen'])
            ->getMock();

        $ssh->expects($this->once())
            ->method('isShellOpen')
            ->willReturn(true);

        $this->assertFalse($ssh->openShell());
    }

    /**
     */
    protected function createSSHMock(): SSH2
    {
        return $this->getMockBuilder('phpseclib3\Net\SSH2')
            ->disableOriginalConstructor()
            ->setMethods(['__destruct'])
            ->getMock();
    }
}
