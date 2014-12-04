<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIV Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Functional_Net_SCPSSH2UserStoryTest extends PhpseclibFunctionalTestCase
{
    static protected $remoteFile;
    static protected $exampleData;
    static protected $exampleDataLength;

    static public function setUpBeforeClass()
    {
        if (getenv('TRAVIS') && version_compare(PHP_VERSION, '5.3.0', '<')) {
            self::markTestIncomplete(
                'This test fails on Travis CI on PHP 5.2 due to requiring GMP.'
            );
        }
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
        $this->assertTrue(
            $scp->put(self::$remoteFile, self::$exampleData),
            'Failed asserting that data could successfully be put() into file.'
        );
        $content = $scp->get(self::$remoteFile);
        $this->assertSame(
            self::$exampleDataLength,
            strlen($content),
            'Failed asserting that string length matches expected length.'
        );
        $this->assertSame(
            self::$exampleData,
            $content,
            'Failed asserting that string content matches expected content.'
        );
        return $scp;
    }

    /** @depends testPutGetString */
    public function testGetFile($scp)
    {
        $localFilename = $this->createTempFile();
        $this->assertTrue(
            $scp->get(self::$remoteFile, $localFilename),
            'Failed asserting that get() into file was successful.'
        );
        $this->assertSame(
            self::$exampleDataLength,
            filesize($localFilename),
            'Failed asserting that filesize matches expected data size.'
        );
        $this->assertSame(
            self::$exampleData,
            file_get_contents($localFilename),
            'Failed asserting that file content matches expected content.'
        );
    }
}
