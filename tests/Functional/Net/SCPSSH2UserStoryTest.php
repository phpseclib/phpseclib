<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'Math/BigInteger.php';

class Functional_Net_SCPSSH2UserStoryTest extends PhpseclibFunctionalTestCase
{
    static protected $remoteFile;
    static protected $exampleData;
    static protected $exampleDataLength;

    static public function setUpBeforeClass()
    {
        parent::setUpBeforeClass();
        self::$remoteFile = uniqid('phpseclib-scp-ssh2-') . '.txt';
        self::$exampleData = str_repeat('abscp12345', 1000);
        self::$exampleDataLength = 10000;
    }

    public function testConstructSSH2()
    {
        $ssh = new Net_SSH2($this->getEnv('SSH_HOSTNAME'));
        $this->assertTrue(
            $ssh->login(
                $this->getEnv('SSH_USERNAME'),
                $this->getEnv('SSH_PASSWORD')
            )
        );
        return $ssh;
    }

    /** @depends testConstructSSH2 */
    public function testConstructor($ssh)
    {
echo "test constructor\r\n";
        $scp = new Net_SCP($ssh);
        $this->assertTrue(
            is_object($scp),
            'Could not construct Net_SCP object.'
        );
        return $scp;
    }

    /** @depends testConstructor */
    public function testPutGetString($scp)
    {
echo "test put get string\r\n";
        $this->assertTrue(
            $scp->put(self::$remoteFile, self::$exampleData),
            'Failed asserting that data could successfully be put() into file.'
        );
        $content = $scp->get(self::$remoteFile);
        // TODO: Address https://github.com/phpseclib/phpseclib/issues/146
        $this->assertContains(
            strlen($content),
            array(self::$exampleDataLength, self::$exampleDataLength + 1),
            'Failed asserting that string length matches expected length.'
        );
        $this->assertContains(
            $content,
            array(self::$exampleData, self::$exampleData . "\0"),
            'Failed asserting that string content matches expected content.'
        );
        return $scp;
    }


}
