<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Functional\Net;

use phpseclib3\Net\SCP;
use phpseclib3\Tests\PhpseclibFunctionalTestCase;

class SCPSSH2UserStoryTest extends PhpseclibFunctionalTestCase
{
    static protected $remoteFile;
    static protected $exampleData;
    static protected $exampleDataLength;

    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();
        self::$remoteFile = uniqid('phpseclib-scp-ssh2-') . '.txt';
        self::$exampleData = str_repeat('abscp12345', 1000);
        self::$exampleDataLength = 10000;
    }

    public function testConstructor()
    {
        $scp = new SCP($this->getEnv('SSH_HOSTNAME'));
        $this->assertTrue(
            $scp->login(
                $this->getEnv('SSH_USERNAME'),
                $this->getEnv('SSH_PASSWORD')
            )
        );
        $this->assertTrue(
            is_object($scp),
            'Could not construct \phpseclib\Net\SCP object.'
        );
        return $scp;
    }

    /**
     * @depends testConstructor
     * @param \phpseclib\Net\SCP $scp
     */
    public function testPutGetString($scp)
    {
        $this->assertTrue(
            $scp->put(self::$remoteFile, self::$exampleData),
            'Failed asserting that data could successfully be put() into file.'
        );
        $content = $scp->get(self::$remoteFile);
        $this->assertSame(
            strlen($content),
            self::$exampleDataLength,
            'Failed asserting that string length matches expected length.'
        );
        $this->assertSame(
            $content,
            self::$exampleData,
            'Failed asserting that string content matches expected content.'
        );
        return $scp;
    }

    /**
     * @depends testPutGetString
     * @param \phpseclib\Net\SCP $scp
     */
    public function testGetFile($scp)
    {
        $localFilename = $this->createTempFile();
        $this->assertTrue(
            $scp->get(self::$remoteFile, $localFilename),
            'Failed asserting that get() into file was successful.'
        );
        $this->assertContains(
            filesize($localFilename),
            array(self::$exampleDataLength, self::$exampleDataLength + 1),
            'Failed asserting that filesize matches expected data size.'
        );
        $this->assertContains(
            file_get_contents($localFilename),
            array(self::$exampleData, self::$exampleData . "\0"),
            'Failed asserting that file content matches expected content.'
        );
        return $scp;
    }

    /**
     * @depends testGetFile
     * @group github873
     */
    public function testGetBadFilePutGet($scp)
    {
        $scp->exec('rm ' . self::$remoteFile);
        $this->assertFalse(
            $scp->get(self::$remoteFile),
            'Failed asserting that get() on a non-existant file failed'
        );
        $this->assertCount(1, $scp->getSCPErrors());
        $this->assertTrue(
            $scp->put(self::$remoteFile, self::$exampleData),
            'Failed asserting that put() succeeded'
        );
        $content = $scp->get(self::$remoteFile);
        $this->assertSame(
            strlen($content),
            self::$exampleDataLength,
            'Failed asserting that string length matches expected length.'
        );
        $this->assertSame(
            $content,
            self::$exampleData,
            'Failed asserting that string content matches expected content.'
        );
        return $scp;
    }
}
