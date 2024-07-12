<?php

/**
 * @author    Marc Scholten <marc@pedigital.de>
 * @copyright 2013 Marc Scholten
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Unit\Net;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Exception\InsufficientSetupException;
use phpseclib3\Exception\TimeoutException;
use phpseclib3\Net\SSH2;
use phpseclib3\Net\SSH2\MessageType;
use phpseclib3\Tests\PhpseclibTestCase;

class SSH2UnitTest extends PhpseclibTestCase
{
    public static function formatLogDataProvider()
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
     * @requires PHPUnit < 10
     */
    public function testFormatLog(array $message_log, array $message_number_log, $expected)
    {
        $ssh = $this->createSSHMock();

        $result = self::callFunc($ssh, 'format_log', [$message_log, $message_number_log]);
        $this->assertEquals($expected, $result);
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testGenerateIdentifier()
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

    /**
     * @requires PHPUnit < 10
     */
    public function testGetExitStatusIfNotConnected()
    {
        $ssh = $this->createSSHMock();

        $this->assertFalse($ssh->getExitStatus());
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testPTYIDefaultValue()
    {
        $ssh = $this->createSSHMock();
        $this->assertFalse($ssh->isPTYEnabled());
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testEnablePTY()
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
    public function testQuietModeDefaultValue()
    {
        $ssh = $this->createSSHMock();

        $this->assertFalse($ssh->isQuietModeEnabled());
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testEnableQuietMode()
    {
        $ssh = $this->createSSHMock();

        $ssh->enableQuietMode();
        $this->assertTrue($ssh->isQuietModeEnabled());

        $ssh->disableQuietMode();
        $this->assertFalse($ssh->isQuietModeEnabled());
    }

    public function testGetConnectionByResourceId()
    {
        $ssh = new SSH2('localhost');
        $this->assertSame($ssh, \phpseclib3\Net\SSH2::getConnectionByResourceId($ssh->getResourceId()));
    }

    public function testGetResourceId()
    {
        $ssh = new SSH2('localhost');
        $this->assertSame('{' . spl_object_hash($ssh) . '}', $ssh->getResourceId());
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testReadUnauthenticated()
    {
        $this->expectException(InsufficientSetupException::class);
        $this->expectExceptionMessage('Operation disallowed prior to login()');

        $ssh = $this->createSSHMock();

        $ssh->read();
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testWriteUnauthenticated()
    {
        $this->expectException(InsufficientSetupException::class);
        $this->expectExceptionMessage('Operation disallowed prior to login()');

        $ssh = $this->createSSHMock();

        $ssh->write('');
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testWriteOpensShell()
    {
        $ssh = $this->getMockBuilder(SSH2::class)
            ->disableOriginalConstructor()
            ->setMethods(['__destruct', 'isAuthenticated', 'openShell', 'send_channel_packet'])
            ->getMock();
        $ssh->expects($this->once())
            ->method('isAuthenticated')
            ->willReturn(true);
        $ssh->expects($this->once())
            ->method('openShell')
            ->willReturn(true);
        $ssh->expects($this->once())
            ->method('send_channel_packet')
            ->with(SSH2::CHANNEL_SHELL, 'hello');

        $ssh->write('hello');
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testOpenShellWhenOpen()
    {
        $ssh = $this->getMockBuilder(SSH2::class)
            ->disableOriginalConstructor()
            ->setMethods(['__destruct'])
            ->getMock();

        $this->expectException(InsufficientSetupException::class);
        $this->expectExceptionMessage('Operation disallowed prior to login()');

        $this->assertFalse($ssh->openShell());
    }

    public function testGetTimeout()
    {
        $ssh = new SSH2('localhost');
        $this->assertEquals(10, $ssh->getTimeout());
        $ssh->setTimeout(0);
        $this->assertEquals(0, $ssh->getTimeout());
        $ssh->setTimeout(20);
        $this->assertEquals(20, $ssh->getTimeout());
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testGetStreamTimeout()
    {
        // no curTimeout, no keepAlive
        $ssh = $this->createSSHMock();
        $this->assertEquals([0, 0], self::callFunc($ssh, 'get_stream_timeout'));

        // curTimeout, no keepAlive
        $ssh = $this->createSSHMock();
        $ssh->setTimeout(1);
        $this->assertEquals([1, 0], self::callFunc($ssh, 'get_stream_timeout'));

        // no curTimeout, keepAlive
        $ssh = $this->createSSHMock();
        $ssh->setKeepAlive(2);
        self::setVar($ssh, 'last_packet', microtime(true));
        list($sec, $usec) = self::callFunc($ssh, 'get_stream_timeout');
        $this->assertGreaterThanOrEqual(1, $sec);
        $this->assertLessThanOrEqual(2, $sec);

        // smaller curTimeout, keepAlive
        $ssh = $this->createSSHMock();
        $ssh->setTimeout(1);
        $ssh->setKeepAlive(2);
        self::setVar($ssh, 'last_packet', microtime(true));
        $this->assertEquals([1, 0], self::callFunc($ssh, 'get_stream_timeout'));

        // curTimeout, smaller keepAlive
        $ssh = $this->createSSHMock();
        $ssh->setTimeout(5);
        $ssh->setKeepAlive(2);
        self::setVar($ssh, 'last_packet', microtime(true));
        list($sec, $usec) = self::callFunc($ssh, 'get_stream_timeout');
        $this->assertGreaterThanOrEqual(1, $sec);
        $this->assertLessThanOrEqual(2, $sec);

        // no curTimeout, keepAlive, no last_packet
        $ssh = $this->createSSHMock();
        $ssh->setKeepAlive(2);
        $this->assertEquals([0, 0], self::callFunc($ssh, 'get_stream_timeout'));

        // no curTimeout, keepAlive, last_packet exceeds keepAlive
        $ssh = $this->createSSHMock();
        $ssh->setKeepAlive(2);
        self::setVar($ssh, 'last_packet', microtime(true) - 2);
        $this->assertEquals([0, 0], self::callFunc($ssh, 'get_stream_timeout'));
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testSendChannelPacketNoBufferedData()
    {
        $ssh = $this->getMockBuilder('phpseclib3\Net\SSH2')
            ->disableOriginalConstructor()
            ->setMethods(['get_channel_packet', 'send_binary_packet'])
            ->getMock();
        $ssh->expects($this->once())
            ->method('get_channel_packet')
            ->with(-1)
            ->willReturnCallback(function () use ($ssh) {
                self::setVar($ssh, 'window_size_client_to_server', [1 => 0x7FFFFFFF]);
            });
        $ssh->expects($this->once())
            ->method('send_binary_packet')
            ->with(Strings::packSSH2('CNs', MessageType::CHANNEL_DATA, 1, 'hello world'));
        self::setVar($ssh, 'server_channels', [1 => 1]);
        self::setVar($ssh, 'packet_size_client_to_server', [1 => 0x7FFFFFFF]);
        self::setVar($ssh, 'window_size_client_to_server', [1 => 0]);
        self::setVar($ssh, 'window_size_server_to_client', [1 => 0x7FFFFFFF]);

        self::callFunc($ssh, 'send_channel_packet', [1, 'hello world']);
        $this->assertEmpty(self::getVar($ssh, 'channel_buffers_write'));
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testSendChannelPacketBufferedData()
    {
        $ssh = $this->getMockBuilder('phpseclib3\Net\SSH2')
            ->disableOriginalConstructor()
            ->setMethods(['get_channel_packet', 'send_binary_packet'])
            ->getMock();
        $ssh->expects($this->once())
            ->method('get_channel_packet')
            ->with(-1)
            ->willReturnCallback(function () use ($ssh) {
                self::setVar($ssh, 'window_size_client_to_server', [1 => 0x7FFFFFFF]);
            });
        $ssh->expects($this->once())
            ->method('send_binary_packet')
            ->with(Strings::packSSH2('CNs', MessageType::CHANNEL_DATA, 1, ' world'));
        self::setVar($ssh, 'channel_buffers_write', [1 => 'hello']);
        self::setVar($ssh, 'server_channels', [1 => 1]);
        self::setVar($ssh, 'packet_size_client_to_server', [1 => 0x7FFFFFFF]);
        self::setVar($ssh, 'window_size_client_to_server', [1 => 0]);
        self::setVar($ssh, 'window_size_server_to_client', [1 => 0x7FFFFFFF]);

        self::callFunc($ssh, 'send_channel_packet', [1, 'hello world']);
        $this->assertEmpty(self::getVar($ssh, 'channel_buffers_write'));
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testSendChannelPacketTimeout()
    {
        $this->expectException(TimeoutException::class);
        $this->expectExceptionMessage('Timed out waiting for server');

        $ssh = $this->getMockBuilder('phpseclib3\Net\SSH2')
            ->disableOriginalConstructor()
            ->setMethods(['get_channel_packet', 'send_binary_packet'])
            ->getMock();
        $ssh->expects($this->once())
            ->method('get_channel_packet')
            ->with(-1)
            ->willReturnCallback(function () use ($ssh) {
                self::setVar($ssh, 'is_timeout', true);
            });
        $ssh->expects($this->once())
            ->method('send_binary_packet')
            ->with(Strings::packSSH2('CNs', MessageType::CHANNEL_DATA, 1, 'hello'));
        self::setVar($ssh, 'server_channels', [1 => 1]);
        self::setVar($ssh, 'packet_size_client_to_server', [1 => 0x7FFFFFFF]);
        self::setVar($ssh, 'window_size_client_to_server', [1 => 5]);
        self::setVar($ssh, 'window_size_server_to_client', [1 => 0x7FFFFFFF]);

        self::callFunc($ssh, 'send_channel_packet', [1, 'hello world']);
        $this->assertEquals([1 => 'hello'], self::getVar($ssh, 'channel_buffers_write'));
    }

    /**
     * @requires PHPUnit < 10
     */
    public function testSendChannelPacketNoWindowAdjustment()
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Data window was not adjusted');

        $ssh = $this->getMockBuilder('phpseclib3\Net\SSH2')
            ->disableOriginalConstructor()
            ->setMethods(['get_channel_packet', 'send_binary_packet'])
            ->getMock();
        $ssh->expects($this->once())
            ->method('get_channel_packet')
            ->with(-1);
        $ssh->expects($this->never())
            ->method('send_binary_packet');
        self::setVar($ssh, 'server_channels', [1 => 1]);
        self::setVar($ssh, 'packet_size_client_to_server', [1 => 0x7FFFFFFF]);
        self::setVar($ssh, 'window_size_client_to_server', [1 => 0]);
        self::setVar($ssh, 'window_size_server_to_client', [1 => 0x7FFFFFFF]);

        self::callFunc($ssh, 'send_channel_packet', [1, 'hello world']);
    }

    /**
     * @return \phpseclib3\Net\SSH2
     */
    protected function createSSHMock()
    {
        return $this->getMockBuilder('phpseclib3\Net\SSH2')
            ->disableOriginalConstructor()
            ->setMethods(['__destruct'])
            ->getMock();
    }
}
