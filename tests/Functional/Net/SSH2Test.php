<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Net\SSH2;

class Functional_Net_SSH2Test extends PhpseclibFunctionalTestCase
{
    public function testConstructor()
    {
        $ssh = new SSH2($this->getEnv('SSH_HOSTNAME'));

        $this->assertTrue(
            is_object($ssh),
            'Could not construct NET_SSH2 object.'
        );

        return $ssh;
    }

    /**
     * @depends testConstructor
     * @group github408
     * @group github412
     */
    public function testPreLogin($ssh)
    {
        $this->assertFalse(
            $ssh->isConnected(),
            'Failed asserting that SSH2 is not connected after construction.'
        );

        $this->assertFalse(
            $ssh->isAuthenticated(),
            'Failed asserting that SSH2 is not authenticated after construction.'
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
    public function testBadPassword($ssh)
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

        return $ssh;
    }

    /**
     * @depends testBadPassword
     */
    public function testPasswordLogin($ssh)
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

        return $ssh;
    }

    /**
     * @depends testPasswordLogin
     * @group github280
     */
    public function testExecWithMethodCallback($ssh)
    {
        $callbackObject = $this->getMockBuilder('stdClass')
            ->setMethods(array('callbackMethod'))
            ->getMock();
        $callbackObject
            ->expects($this->atLeastOnce())
            ->method('callbackMethod')
            ->will($this->returnValue(true));
        $ssh->exec('pwd', array($callbackObject, 'callbackMethod'));

        return $ssh;
    }

    public function testGetServerPublicHostKey()
    {
        $ssh = new SSH2($this->getEnv('SSH_HOSTNAME'));

        $this->assertIsString($ssh->getServerPublicHostKey());
    }

    public function testOpenSocketConnect()
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
    public function testDisablePTY($ssh)
    {
        $ssh->enablePTY();
        $ssh->exec('ls -latr');
        $ssh->disablePTY();
        $ssh->exec('pwd');

        $this->assertTrue(true);

        return $ssh;
    }

    /**
     * @depends testDisablePTY
     * @group github1167
     */
    public function testChannelDataAfterOpen($ssh)
    {
        $ssh->write("ping 127.0.0.1\n");

        $ssh->enablePTY();
        $ssh->exec('bash');

        $ssh->write("ls -latr\n");

        $ssh->setTimeout(1);

        $ssh->read();
    }
}
