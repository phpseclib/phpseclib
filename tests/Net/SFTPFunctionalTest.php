<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIV Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Net_SFTPFunctionalTest extends PhpseclibFunctionalTestCase
{
    static protected $scratchDir;
    static protected $exampleData;
    static protected $exampleDataLength;

    static public function setUpBeforeClass()
    {
        if (getenv('TRAVIS') && version_compare(PHP_VERSION, '5.3.3', '<=')) {
            self::markTestIncomplete(
                'This test hangs on Travis CI on PHP 5.3.3 and below.'
            );
        }

        parent::setUpBeforeClass();

        self::$scratchDir = uniqid('phpseclib-sftp-scratch-');

        self::$exampleData = str_repeat('abcde12345', 1000);
        self::$exampleDataLength = 10000;
    }

    public function testConstructor()
    {
        $sftp = new Net_SFTP($this->getEnv('SSH_HOSTNAME'));

        $this->assertTrue(
            is_object($sftp),
            'Could not construct NET_SFTP object.'
        );

        return $sftp;
    }

    /**
    * @depends testConstructor
    */
    public function testPasswordLogin($sftp)
    {
        $username = $this->getEnv('SSH_USERNAME');
        $password = $this->getEnv('SSH_PASSWORD');
        $this->assertTrue(
            $sftp->login($username, $password),
            'SSH2/SFTP login using password failed.'
        );

        return $sftp;
    }

    /**
    * @depends testPasswordLogin
    */
    public function testPwdHome($sftp)
    {
        $this->assertEquals(
            $this->getEnv('SSH_HOME'),
            $sftp->pwd(),
            'Failed asserting that pwd() returns home directory after login.'
        );

        return $sftp;
    }

    /**
    * @depends testPwdHome
    */
    public function testMkDirScratch($sftp)
    {
        $dirname = self::$scratchDir;

        $this->assertTrue(
            $sftp->mkdir($dirname),
            "Failed asserting that a new scratch directory $dirname could " .
            'be created.'
        );

        $this->assertFalse(
            $sftp->mkdir($dirname),
            "Failed asserting that a new scratch directory $dirname could " .
            'not be created (because it already exists).'
        );

        return $sftp;
    }

    /**
    * @depends testMkDirScratch
    */
    public function testChDirScratch($sftp)
    {
        $this->assertTrue(
            $sftp->chdir(self::$scratchDir),
            sprintf(
                'Failed asserting that working directory could be changed ' .
                'to scratch directory %s.',
                self::$scratchDir
            )
        );

        $pwd = $sftp->pwd();

        $this->assertStringStartsWith(
            $this->getEnv('SSH_HOME'),
            $pwd,
            'Failed asserting that the home directory is a prefix of the ' .
            'current working directory.'
        );

        $this->assertStringEndsWith(
            self::$scratchDir,
            $pwd,
            'Failed asserting that the scratch directory name is a suffix ' .
            'of the current working directory.'
        );

        return $sftp;
    }

    /**
    * @depends testChDirScratch
    */
    public function testStatOnDir($sftp)
    {
        $this->assertNotSame(
            array(),
            $sftp->stat('.'),
            'Failed asserting that the cwd has a non-empty stat.'
        );

        return $sftp;
    }

    /**
    * @depends testStatOnDir
    */
    public function testPutSizeGetFile($sftp)
    {
        $this->assertTrue(
            $sftp->put('file1.txt', self::$exampleData),
            'Failed asserting that example data could be successfully put().'
        );

        $this->assertSame(
            self::$exampleDataLength,
            $sftp->size('file1.txt'),
            'Failed asserting that put example data has the expected length'
        );

        $this->assertSame(
            self::$exampleData,
            $sftp->get('file1.txt'),
            'Failed asserting that get() returns expected example data.'
        );

        return $sftp;
    }

    /**
    * @depends testPutSizeGetFile
    */
    public function testChDirOnFile($sftp)
    {
        $this->assertFalse(
            $sftp->chdir('file1.txt'),
            'Failed to assert that the cwd cannot be changed to a file'
        );

        return $sftp;
    }

    /**
    * @depends testChDirOnFile
    */
    public function testFileExistsIsFileIsDirFile($sftp)
    {
        $this->assertTrue(
            $sftp->file_exists('file1.txt'),
            'Failed asserting that file_exists() on example file returns true.'
        );

        $this->assertTrue(
            $sftp->is_file('file1.txt'),
            'Failed asserting that is_file() on example file returns true.'
        );

        $this->assertFalse(
            $sftp->is_dir('file1.txt'),
            'Failed asserting that is_dir() on example file returns false.'
        );

        return $sftp;
    }

    /**
    * @depends testFileExistsIsFileIsDirFile
    */
    public function testFileExistsIsFileIsDirFileNonexistent($sftp)
    {
        $this->assertFalse(
            $sftp->file_exists('file2.txt'),
            'Failed asserting that a nonexistent file does not exist.'
        );

        $this->assertFalse(
            $sftp->is_file('file2.txt'),
            'Failed asserting that is_file() on nonexistent file returns false.'
        );

        $this->assertFalse(
            $sftp->is_dir('file2.txt'),
            'Failed asserting that is_dir() on nonexistent file returns false.'
        );

        return $sftp;
    }

    /**
    * @depends testFileExistsIsFileIsDirFileNonexistent
    */
    public function testChDirUpHome($sftp)
    {
        $this->assertTrue(
            $sftp->chdir('../'),
            'Failed asserting that directory could be changed one level up.'
        );

        $this->assertEquals(
            $this->getEnv('SSH_HOME'),
            $sftp->pwd(),
            'Failed asserting that pwd() returns home directory.'
        );

        return $sftp;
    }

    /**
    * @depends testChDirUpHome
    */
    public function testFileExistsIsFileIsDirDir($sftp)
    {
        $this->assertTrue(
            $sftp->file_exists(self::$scratchDir),
            'Failed asserting that file_exists() on scratch dir returns true.'
        );

        $this->assertFalse(
            $sftp->is_file(self::$scratchDir),
            'Failed asserting that is_file() on example file returns false.'
        );

        $this->assertTrue(
            $sftp->is_dir(self::$scratchDir),
            'Failed asserting that is_dir() on example file returns true.'
        );

        return $sftp;
    }

    /**
    * @depends testFileExistsIsFileIsDirDir
    */
    public function testRmDirScratch($sftp)
    {
        $this->assertFalse(
            $sftp->rmdir(self::$scratchDir),
            'Failed asserting that non-empty scratch directory could ' .
            'not be deleted using rmdir().'
        );

        return $sftp;
    }

    /**
    * @depends testRmDirScratch
    */
    public function testDeleteRecursiveScratch($sftp)
    {
        $this->assertTrue(
            $sftp->delete(self::$scratchDir),
            'Failed asserting that non-empty scratch directory could ' .
            'be deleted using recursive delete().'
        );

        return $sftp;
    }

    /**
    * @depends testDeleteRecursiveScratch
    */
    public function testRmDirScratchNonexistent($sftp)
    {
        $this->assertFalse(
            $sftp->rmdir(self::$scratchDir),
            'Failed asserting that nonexistent scratch directory could ' .
            'not be deleted using rmdir().'
        );
    }
}
