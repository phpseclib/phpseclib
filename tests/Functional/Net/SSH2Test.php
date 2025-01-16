<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib3\Tests\Functional\Net;

use phpseclib3\Exception\NoSupportedAlgorithmsException;
use phpseclib3\Net\SSH2;
use phpseclib3\Tests\PhpseclibFunctionalTestCase;

class SSH2Test extends PhpseclibFunctionalTestCase
{
    public function getSSH2(): SSH2
    {
        return new SSH2($this->getEnv('SSH_HOSTNAME'), 22);
    }

    public function getSSH2Login(): SSH2
    {
        $ssh = $this->getSSH2();

        $username = $this->getEnv('SSH_USERNAME');
        $password = $this->getEnv('SSH_PASSWORD');
        $this->assertTrue(
            $ssh->login($username, $password),
            'SSH2 login using password failed.'
        );

        return $ssh;
    }

    public function testConstructor(): SSH2
    {
        $ssh = $this->getSSH2();

        $this->assertIsObject(
            $ssh,
            'Could not construct NET_SSH2 object.'
        );

        return $ssh;
    }

    /**
     * @depends testConstructor
     * @group github408
     * @group github412
     */
    public function testPreLogin(SSH2 $ssh): SSH2
    {
        $this->assertFalse(
            $ssh->isConnected(),
            'Failed asserting that SSH2 is not connected after construction.'
        );

        $this->assertFalse(
            $ssh->isAuthenticated(),
            'Failed asserting that SSH2 is not authenticated after construction.'
        );

        $this->assertFalse(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 does not have open shell after construction.'
        );

        $this->assertEquals(
            0,
            $ssh->getInteractiveChannelId(),
            'Failed asserting that channel identifier 0 is returned.'
        );

        $this->assertNotEmpty(
            $ssh->getServerPublicHostKey(),
            'Failed asserting that a non-empty public host key was fetched.'
        );

        $this->assertTrue(
            $ssh->isConnected(),
            'Failed asserting that SSH2 is connected after public key fetch.'
        );

        $this->assertNotEmpty(
            $ssh->getServerIdentification(),
            'Failed asserting that the server identifier was set after connect.'
        );

        return $ssh;
    }

    /**
     * @depends testPreLogin
     */
    public function testBadPassword(SSH2 $ssh): SSH2
    {
        $username = $this->getEnv('SSH_USERNAME');
        $password = $this->getEnv('SSH_PASSWORD');
        $this->assertFalse(
            $ssh->login($username, 'zzz' . $password),
            'SSH2 login using password succeeded.'
        );

        $this->assertTrue(
            $ssh->isConnected(),
            'Failed asserting that SSH2 is connected after bad login attempt.'
        );

        $this->assertFalse(
            $ssh->isAuthenticated(),
            'Failed asserting that SSH2 is not authenticated after bad login attempt.'
        );

        $this->assertFalse(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 does not have open shell after bad login attempt.'
        );

        return $ssh;
    }

    /**
     * @depends testBadPassword
     */
    public function testPasswordLogin(SSH2 $ssh): SSH2
    {
        $username = $this->getEnv('SSH_USERNAME');
        $password = $this->getEnv('SSH_PASSWORD');
        $this->assertTrue(
            $ssh->login($username, $password),
            'SSH2 login using password failed.'
        );

        $this->assertTrue(
            $ssh->isAuthenticated(),
            'Failed asserting that SSH2 is authenticated after good login attempt.'
        );

        $this->assertFalse(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 does not have open shell after good login attempt.'
        );

        return $ssh;
    }

    /**
     * @depends testPasswordLogin
     * @group github280
     * @requires PHPUnit < 10
     */
    public function testExecWithMethodCallback(SSH2 $ssh): SSH2
    {
        $callbackObject = $this->getMockBuilder('stdClass')
            ->setMethods(['callbackMethod'])
            ->getMock();
        $callbackObject
            ->expects($this->atLeastOnce())
            ->method('callbackMethod')
            ->will($this->returnValue(true));
        $ssh->exec('pwd', [$callbackObject, 'callbackMethod']);

        $this->assertFalse(
            $ssh->isPTYOpen(),
            'Failed asserting that SSH2 does not have open exec channel after exec.'
        );

        $this->assertFalse(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 does not have open shell channel after exec.'
        );

        $this->assertEquals(
            0,
            $ssh->getInteractiveChannelId(),
            'Failed asserting that channel identifier 0 is returned after exec.'
        );

        return $ssh;
    }

    public function testGetServerPublicHostKey(): void
    {
        $ssh = $this->getSSH2();

        $this->assertIsString($ssh->getServerPublicHostKey());
    }

    public function testOpenSocketConnect(): void
    {
        $fsock = fsockopen($this->getEnv('SSH_HOSTNAME'), 22);
        $ssh = new SSH2($fsock);

        $username = $this->getEnv('SSH_USERNAME');
        $password = $this->getEnv('SSH_PASSWORD');
        $this->assertTrue(
            $ssh->login($username, $password),
            'SSH2 login using an open socket failed.'
        );
    }

    /**
     * @depends testExecWithMethodCallback
     * @group github1009
     */
    public function testDisablePTY(SSH2 $ssh): SSH2
    {
        $ssh->enablePTY();

        $this->assertTrue(
            $ssh->isPTYEnabled(),
            'Failed asserting that pty was enabled.'
        );

        $this->assertFalse(
            $ssh->isPTYOpen(),
            'Failed asserting that pty was not open after enable.'
        );

        $this->assertEquals(
            0,
            $ssh->getInteractiveChannelId(),
            'Failed asserting that 0 channel identifier is returned prior to opening.'
        );

        $ssh->exec('ls -latr');

        $this->assertTrue(
            $ssh->isPTYOpen(),
            'Failed asserting that pty was open.'
        );

        $this->assertFalse(
            $ssh->isShellOpen(),
            'Failed asserting that shell was not open after pty exec.'
        );

        $this->assertEquals(
            SSH2::CHANNEL_EXEC,
            $ssh->getInteractiveChannelId(),
            'Failed asserting that exec channel identifier is returned after exec.'
        );

        $ssh->disablePTY();

        $this->assertFalse(
            $ssh->isPTYEnabled(),
            'Failed asserting that pty was disabled.'
        );

        $this->assertFalse(
            $ssh->isPTYOpen(),
            'Failed asserting that pty was not open after disable.'
        );

        $this->assertEquals(
            SSH2::CHANNEL_EXEC,
            $ssh->getInteractiveChannelId(),
            'Failed asserting that exec channel identifier is returned after pty exec close.'
        );

        $ssh->exec('pwd');

        $this->assertFalse(
            $ssh->isPTYOpen(),
            'Failed asserting that pty was not open after exec.'
        );

        return $ssh;
    }

    /**
     * @depends testDisablePTY
     * @group github1167
     */
    public function testChannelDataAfterOpen(SSH2 $ssh): void
    {
        // Ubuntu's OpenSSH from 5.8 to 6.9 didn't work with multiple channels. see
        // https://bugs.launchpad.net/ubuntu/+source/openssh/+bug/1334916 for more info.
        // https://lists.ubuntu.com/archives/oneiric-changes/2011-July/005772.html discusses
        // when consolekit was incorporated.
        // https://marc.info/?l=openssh-unix-dev&m=163409903417589&w=2 discusses some of the
        // issues with how Ubuntu incorporated consolekit
        $pattern = '#^SSH-2\.0-OpenSSH_([\d.]+)[^ ]* Ubuntu-.*$#';
        $match = preg_match($pattern, $ssh->getServerIdentification(), $matches);
        $match = $match && version_compare('5.8', $matches[1], '<=');
        $match = $match && version_compare('6.9', $matches[1], '>=');
        if ($match) {
            self::markTestSkipped('Ubuntu\'s OpenSSH >= 5.8 <= 6.9 didn\'t work well with multiple channels');
        }

        $ssh->write("ping 127.0.0.1\n");

        $this->assertTrue(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 has open shell after shell read/write.'
        );

        $this->assertFalse(
            $ssh->isPTYOpen(),
            'Failed asserting that pty was not open after shell read/write.'
        );

        $this->assertEquals(
            SSH2::CHANNEL_SHELL,
            $ssh->getInteractiveChannelId(),
            'Failed asserting that shell channel identifier is returned after shell read/write.'
        );

        $ssh->enablePTY();

        $this->assertTrue(
            $ssh->exec('bash'),
            'Failed asserting exec command succeeded.'
        );

        $this->assertTrue(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 has open shell after pty exec.'
        );

        $this->assertTrue(
            $ssh->isPTYOpen(),
            'Failed asserting that pty was not open after exec.'
        );

        $this->assertEquals(
            SSH2::CHANNEL_EXEC,
            $ssh->getInteractiveChannelId(),
            'Failed asserting that exec channel identifier is returned after pty exec.'
        );

        $ssh->write("ls -latr\n");

        $ssh->setTimeout(1);

        $this->assertIsString($ssh->read());

        $this->assertTrue(
            $ssh->isTimeout(),
            'Failed asserting that pty exec read timed out'
        );

        $this->assertTrue(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 shell remains open across pty exec read/write.'
        );

        $this->assertTrue(
            $ssh->isPTYOpen(),
            'Failed asserting that pty was open after read timeout.'
        );
    }

    public function testOpenShell(): SSH2
    {
        $ssh = $this->getSSH2Login();

        $this->assertTrue(
            $ssh->openShell(),
            'SSH2 shell initialization failed.'
        );

        $this->assertTrue(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 has open shell after init.'
        );

        $this->assertNotFalse(
            $ssh->read(),
            'Failed asserting that read succeeds.'
        );

        $ssh->write('hello');

        $this->assertTrue(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 has open shell after read/write.'
        );

        $this->assertEquals(
            SSH2::CHANNEL_SHELL,
            $ssh->getInteractiveChannelId(),
            'Failed asserting that shell channel identifier is returned after read/write.'
        );

        return $ssh;
    }

    /**
     * @depends testOpenShell
     */
    public function testResetOpenShell(SSH2 $ssh): void
    {
        $ssh->reset();

        $this->assertFalse(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 has open shell after reset.'
        );

        $this->assertEquals(
            SSH2::CHANNEL_SHELL,
            $ssh->getInteractiveChannelId(),
            'Failed asserting that shell channel identifier is returned after reset.'
        );
    }

    public function testMultipleExecPty(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Please close the channel (1) before trying to open it again');

        $ssh = $this->getSSH2Login();

        $ssh->enablePTY();

        $ssh->exec('bash');

        $ssh->exec('bash');
    }

    public function testMultipleInteractiveChannels(): void
    {
        $ssh = $this->getSSH2Login();

        $this->assertTrue(
            $ssh->openShell(),
            'SSH2 shell initialization failed.'
        );

        $this->assertEquals(
            SSH2::CHANNEL_SHELL,
            $ssh->getInteractiveChannelId(),
            'Failed asserting that shell channel identifier is returned after open shell.'
        );

        $ssh->setTimeout(1);

        $this->assertIsString(
            $ssh->read(),
            'Failed asserting that read succeeds after shell init'
        );

        $directory = $ssh->exec('pwd');

        $this->assertFalse(
            $ssh->isTimeout(),
            'failed'
        );

        $this->assertIsString(
            $directory,
            'Failed asserting that exec succeeds after shell read/write'
        );

        $ssh->write("pwd\n");

        $this->assertStringContainsString(
            trim($directory),
            $ssh->read(),
            'Failed asserting that current directory can be read from shell after exec'
        );

        $ssh->enablePTY();

        $this->assertTrue(
            $ssh->exec('bash'),
            'Failed asserting that pty exec succeeds'
        );

        $this->assertTrue(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 has open shell after pty exec.'
        );

        $this->assertEquals(
            SSH2::CHANNEL_EXEC,
            $ssh->getInteractiveChannelId(),
            'Failed asserting that exec channel identifier is returned after pty exec.'
        );

        $ssh->write("pwd\n", SSH2::CHANNEL_SHELL);

        $this->assertStringContainsString(
            trim($directory),
            $ssh->read('', SSH2::READ_SIMPLE, SSH2::CHANNEL_SHELL),
            'Failed asserting that current directory can be read from shell after pty exec'
        );

        $this->assertTrue(
            $ssh->isPTYOpen(),
            'Failed asserting that SSH2 has open pty exec after shell read/write.'
        );

        $ssh->write("pwd\n", SSH2::CHANNEL_EXEC);

        $this->assertIsString(
            $ssh->read('', SSH2::READ_SIMPLE, SSH2::CHANNEL_EXEC),
            'Failed asserting that pty exec read succeeds'
        );

        $ssh->reset(SSH2::CHANNEL_EXEC);

        $this->assertFalse(
            $ssh->isPTYOpen(),
            'Failed asserting that SSH2 has closed pty exec after reset.'
        );

        $ssh->disablePTY();

        $this->assertTrue(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 has open shell after pty exec.'
        );

        $ssh->write("pwd\n", SSH2::CHANNEL_SHELL);

        $this->assertStringContainsString(
            trim($directory),
            $ssh->read('', SSH2::READ_SIMPLE, SSH2::CHANNEL_SHELL),
            'Failed asserting that current directory can be read from shell after pty exec'
        );

        $ssh->reset(SSH2::CHANNEL_SHELL);

        $this->assertFalse(
            $ssh->isShellOpen(),
            'Failed asserting that SSH2 has closed shell after reset.'
        );

        $this->assertEquals(
            SSH2::CHANNEL_EXEC,
            $ssh->getInteractiveChannelId(),
            'Failed asserting that exec channel identifier is maintained as last opened channel.'
        );
    }

    public function testReadingOfClosedChannel(): void
    {
        $ssh = $this->getSSH2Login();
        $this->assertSame(0, $ssh->getOpenChannelCount());
        $ssh->enablePTY();
        $ssh->exec('ping -c 3 127.0.0.1; exit');
        $ssh->write("ping 127.0.0.2\n", SSH2::CHANNEL_SHELL);
        $ssh->setTimeout(3);
        $output = $ssh->read('', SSH2::READ_SIMPLE, SSH2::CHANNEL_SHELL);
        $this->assertStringContainsString('PING 127.0.0.2', $output);
        $output = $ssh->read('', SSH2::READ_SIMPLE, SSH2::CHANNEL_EXEC);
        $this->assertStringContainsString('PING 127.0.0.1', $output);
        $this->assertSame(1, $ssh->getOpenChannelCount());
        $ssh->reset(SSH2::CHANNEL_SHELL);
        $this->assertSame(0, $ssh->getOpenChannelCount());
    }

    public function testPing(): void
    {
        $ssh = $this->getSSH2();
        // assert on unauthenticated ssh2
        $this->assertNotEmpty($ssh->getServerIdentification());
        $this->assertFalse($ssh->ping());
        $this->assertTrue($ssh->isConnected());
        $this->assertSame(0, $ssh->getOpenChannelCount());

        $ssh = $this->getSSH2Login();
        $this->assertTrue($ssh->ping());
        $this->assertSame(0, $ssh->getOpenChannelCount());
    }

    public function testKeepAlive(): void
    {
        $ssh = $this->getSSH2();
        $username = $this->getEnv('SSH_USERNAME');
        $password = $this->getEnv('SSH_PASSWORD');

        $ssh->setKeepAlive(1);
        $ssh->setTimeout(1);

        $this->assertNotEmpty($ssh->getServerIdentification());
        $this->assertTrue(
            $ssh->login($username, $password),
            'SSH2 login using password failed.'
        );

        $ssh->write("pwd\n");
        sleep(1); // permit keep alive to proc on next read
        $this->assertNotEmpty($ssh->read('', SSH2::READ_NEXT));
        $ssh->disconnect();
    }

    /**
     * @return array
     */
    public static function getCryptoAlgorithms()
    {
        $map = [
            'kex' => SSH2::getSupportedKEXAlgorithms(),
            'hostkey' => SSH2::getSupportedHostKeyAlgorithms(),
            'comp' => SSH2::getSupportedCompressionAlgorithms(),
            'crypt' => SSH2::getSupportedEncryptionAlgorithms(),
            'mac' => SSH2::getSupportedMACAlgorithms(),
        ];
        $tests = [];
        foreach ($map as $type => $algorithms) {
            foreach ($algorithms as $algorithm) {
                $tests[] = [$type, $algorithm];
            }
        }
        return $tests;
    }

    /**
     * @group github2062
     */
    public function testSendEOF()
    {
        $ssh = $this->getSSH2Login();

        $ssh->write("ls -latr; exit\n");
        $ssh->read();
        $ssh->sendEOF();
        $ssh->exec('ls -latr');
    }

    /**
     * @dataProvider getCryptoAlgorithms
     * @param string $type
     * @param string $algorithm
     */
    public function testCryptoAlgorithms($type, $algorithm): void
    {
        $ssh = $this->getSSH2();
        try {
            switch ($type) {
                case 'kex':
                case 'hostkey':
                    $ssh->setPreferredAlgorithms([$type => [$algorithm]]);
                    $this->assertEquals($algorithm, $ssh->getAlgorithmsNegotiated()[$type]);
                    break;
                case 'comp':
                case 'crypt':
                    $ssh->setPreferredAlgorithms([
                        'client_to_server' => [$type => [$algorithm]],
                        'server_to_client' => [$type => [$algorithm]],
                    ]);
                    $this->assertEquals($algorithm, $ssh->getAlgorithmsNegotiated()['client_to_server'][$type]);
                    $this->assertEquals($algorithm, $ssh->getAlgorithmsNegotiated()['server_to_client'][$type]);
                    break;
                case 'mac':
                    $macCryptAlgorithms = array_filter(
                        SSH2::getSupportedEncryptionAlgorithms(),
                        function ($algorithm) use ($ssh) {
                            return !self::callFunc($ssh, 'encryption_algorithm_to_crypt_instance', [$algorithm])
                                ->usesNonce();
                        }
                    );
                    $ssh->setPreferredAlgorithms([
                        'client_to_server' => ['crypt' => $macCryptAlgorithms, 'mac' => [$algorithm]],
                        'server_to_client' => ['crypt' => $macCryptAlgorithms, 'mac' => [$algorithm]],
                    ]);
                    $this->assertEquals($algorithm, $ssh->getAlgorithmsNegotiated()['client_to_server']['mac']);
                    $this->assertEquals($algorithm, $ssh->getAlgorithmsNegotiated()['server_to_client']['mac']);
                    break;
            }
        } catch (NoSupportedAlgorithmsException $e) {
            self::markTestSkipped("{$type} algorithm {$algorithm} is not supported by server");
        }

        $username = $this->getEnv('SSH_USERNAME');
        $password = $this->getEnv('SSH_PASSWORD');
        $this->assertTrue(
            $ssh->login($username, $password),
            "SSH2 login using {$type} {$algorithm} failed."
        );

        $ssh->setTimeout(1);
        $ssh->write("pwd\n");
        $this->assertNotEmpty($ssh->read('', SSH2::READ_NEXT));
        $ssh->disconnect();
    }
}
