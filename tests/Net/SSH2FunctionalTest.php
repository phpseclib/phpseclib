<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIV Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Net_SSH2FunctionalTest extends PhpseclibFunctionalTestCase
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
    */
    public function testPasswordLogin($ssh)
    {
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
        $callbackObject = $this->getMock('stdClass', array('callbackMethod'));
        $callbackObject
            ->expects($this->atLeastOnce())
            ->method('callbackMethod')
            ->will($this->returnValue(true));
        $ssh->exec('pwd', array($callbackObject, 'callbackMethod'));
    }
}
