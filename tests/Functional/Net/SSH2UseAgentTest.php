<?php
/**
 * @author    Chris Kruger <chris.kruger@mokosocialmedia.com>
 * @copyright MMXIV Chris Kruger
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Functional_Net_SSH2UseAgentTest extends PhpseclibFunctionalTestCase
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
    public function testAgentLogin($ssh) 
    {
        $agent = new System_SSH_Agent(true);
        $username = $this->getEnv('SSH_USERNAME'); 
        $this->assertTrue(
            $ssh->login($username, $agent),
            'SSH2 login using agent failed.'
        );

        return $ssh;
    }

    /**
    * @depends testAgentLogin
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

    /**
     * @depends testAgentLogin
     */
    public function testAgentForward($ssh) 
    {
        $callbackObject = $this->getMock('stdClass', array('callbackMethod'));
        $callbackObject
            ->expects($this->atLeastOnce())
            ->method('callbackMethod')
            ->will($this->returnValue(true));

        $ssh->exec('ssh -T git@bitbucket.org', array($callbackObject, 'callbackMethod'));
    }
}
