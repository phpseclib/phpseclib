<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Functional_Net_SSH2Test extends PhpseclibFunctionalTestCase
{
    public function setUp()
    {
        if (getenv('TRAVIS') && version_compare(PHP_VERSION, '5.3.3', '<=')) {
            $this->markTestIncomplete(
                'This test hangs on Travis CI on PHP 5.3.3 and below.'
            );
        }
        parent::setUp();
    }

    public function testConstructor()
    {
        $ssh = new Net_SSH2($this->getEnv('SSH_HOSTNAME'));

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
echo "zzz test pre login\r\n";
        $this->assertFalse(
            $ssh->isConnected(),
            'Failed asserting that SSH2 is not connected after construction.'
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
    public function testPasswordLogin($ssh)
    {
echo "zzz test pw login\r\n";
        $username = $this->getEnv('SSH_USERNAME');
        $password = $this->getEnv('SSH_PASSWORD');
        $this->assertTrue(
            $ssh->login($username, $password),
            'SSH2 login using password failed.'
        );

        return $ssh;
    }

    /**
    * @depends testPasswordLogin
    * @group github280
    */
    public function testExecWithMethodCallback($ssh)
    {
echo "zzz test exec with method callback\r\n";
        $callbackObject = $this->getMock('stdClass', array('callbackMethod'));
        $callbackObject
            ->expects($this->atLeastOnce())
            ->method('callbackMethod')
            ->will($this->returnValue(true));
        $ssh->exec('pwd', array($callbackObject, 'callbackMethod'));
    }

    public function testGetServerPublicHostKey()
    {
echo "zzz test get server public key host\r\n";
        $ssh = new Net_SSH2($this->getEnv('SSH_HOSTNAME'));

        $this->assertInternalType('string', $ssh->getServerPublicHostKey());
    }
}
