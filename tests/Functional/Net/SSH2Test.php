<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib3\Tests\Functional\Net;

use phpseclib3\Net\SSH2;
use phpseclib3\Tests\PhpseclibFunctionalTestCase;

class SSH2Test extends PhpseclibFunctionalTestCase
{
    /**
     * @return SSH2
     */
    public function getSSH2(): SSH2
    {
        return new SSH2($this->getEnv('SSH_HOSTNAME'), 22);
    }

    /**
     * @return SSH2
     */
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

        $ssh->exec('ls -latr');

        $this->assertTrue(
            $ssh->isPTYOpen(),
            'Failed asserting that pty was open.'
        );

        $this->assertFalse(
            $ssh->isShellOpen(),
            'Failed asserting that shell was not open after pty exec.'
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
    }

    public function testMultipleExecPty(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('If you want to run multiple exec()\'s you will need to disable (and re-enable if appropriate) a PTY for each one.');

        $ssh = $this->getSSH2Login();

        $ssh->enablePTY();

        $ssh->exec('bash');

        $ssh->exec('bash');
    }

    public function testMultipleInteractiveChannels()
    {
        $ssh = $this->getSSH2Login();

        $this->assertTrue(
            $ssh->openShell(),
            'SSH2 shell initialization failed.'
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
    }
}
