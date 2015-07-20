<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Net\SFTP;

class Functional_Net_SFTPUserStoryTest extends PhpseclibFunctionalTestCase
{
    static protected $scratchDir;
    static protected $exampleData;
    static protected $exampleDataLength;
    static protected $buffer;

    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();

        self::$scratchDir = uniqid('phpseclib-sftp-scratch-');

        self::$exampleData = str_repeat('abcde12345', 1000);
        self::$exampleDataLength = 10000;
    }

    public function testConstructor()
    {
        $sftp = new SFTP($this->getEnv('SSH_HOSTNAME'));

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

    static function callback($length)
    {
        $r = substr(self::$buffer, 0, $length);
        self::$buffer = substr(self::$buffer, $length);
        if (strlen($r)) {
            return $r;
        }
        return null;
    }

    /**
    * @depends testStatOnDir
    */
    public function testPutSizeGetFileCallback($sftp)
    {
        self::$buffer = self::$exampleData;
        $this->assertTrue(
            $sftp->put('file1.txt', array(__CLASS__, 'callback'), $sftp::SOURCE_CALLBACK),
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
    public function testTouch($sftp)
    {
        $this->assertTrue(
            $sftp->touch('file2.txt'),
            'Failed asserting that touch() successfully ran.'
        );

        $this->assertTrue(
            $sftp->file_exists('file2.txt'),
            'Failed asserting that touch()\'d file exists'
        );

        return $sftp;
    }

    /**
     * @depends testTouch
     */
    public function testTruncate($sftp)
    {
        $this->assertTrue(
            $sftp->touch('file3.txt'),
            'Failed asserting that touch() successfully ran.'
        );

        $this->assertTrue(
            $sftp->truncate('file3.txt', 1024 * 1024),
            'Failed asserting that touch() successfully ran.'
        );

        $this->assertSame(
            1024 * 1024,
            $sftp->size('file3.txt'),
            'Failed asserting that truncate()\'d file has the expected length'
        );

        return $sftp;
    }

    /**
     * @depends testTruncate
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
            $sftp->file_exists('file4.txt'),
            'Failed asserting that a nonexistent file does not exist.'
        );

        $this->assertFalse(
            $sftp->is_file('file4.txt'),
            'Failed asserting that is_file() on nonexistent file returns false.'
        );

        $this->assertFalse(
            $sftp->is_dir('file4.txt'),
            'Failed asserting that is_dir() on nonexistent file returns false.'
        );

        return $sftp;
    }

    /**
     * @depends testFileExistsIsFileIsDirFileNonexistent
     */
    public function testSortOrder($sftp)
    {
        $this->assertTrue(
            $sftp->mkdir('temp'),
            "Failed asserting that a new scratch directory temp could " .
            'be created.'
        );

        $sftp->setListOrder('filename', SORT_DESC);

        $list = $sftp->nlist();
        $expected = array('.', '..', 'temp', 'file3.txt', 'file2.txt', 'file1.txt');

        $this->assertSame(
            $list,
            $expected,
            'Failed asserting that list sorted correctly.'
        );

        $sftp->setListOrder('filename', SORT_ASC);

        $list = $sftp->nlist();
        $expected = array('.', '..', 'temp', 'file1.txt', 'file2.txt', 'file3.txt');

        $this->assertSame(
            $list,
            $expected,
            'Failed asserting that list sorted correctly.'
        );

        $sftp->setListOrder('size', SORT_DESC);

        $files = $sftp->nlist();

        $last_size = 0x7FFFFFFF;
        foreach ($files as $file) {
            if ($sftp->is_file($file)) {
                $cur_size = $sftp->size($file);
                $this->assertLessThanOrEqual(
                    $last_size,
                    $cur_size,
                    'Failed asserting that nlist() is in descending order'
                );
                $last_size = $cur_size;
            }
        }

        return $sftp;
    }

    /**
     * @depends testSortOrder
     */
    public function testResourceXfer($sftp)
    {
        $fp = fopen('res.txt', 'w+');
        $sftp->get('file1.txt', $fp);
        rewind($fp);
        $sftp->put('file4.txt', $fp);
        fclose($fp);

        $this->assertSame(
            self::$exampleData,
            $sftp->get('file4.txt'),
            'Failed asserting that a file downloaded into a resource and reuploaded from a resource has the correct data'
        );

        return $sftp;
    }

    /**
     * @depends testResourceXfer
     */
    public function testSymlink($sftp)
    {
        $this->assertTrue(
            $sftp->symlink('file3.txt', 'symlink'),
            'Failed asserting that a symlink could be created'
        );

        return $sftp;
    }

    /**
     * @depends testSymlink
     */
    public function testStatLstatCache($sftp)
    {
        $stat = $sftp->stat('symlink');
        $lstat = $sftp->lstat('symlink');
        $this->assertNotEquals(
            $stat,
            $lstat,
            'Failed asserting that stat and lstat returned different output for a symlink'
        );

        return $sftp;
    }

    /**
     * @depends testStatLstatCache
     */
    public function testLinkFile($sftp)
    {
        $this->assertTrue(
            $sftp->is_link('symlink'),
            'Failed asserting that symlink is a link'
        );
        $this->assertTrue(
            $sftp->is_file('symlink'),
            'Failed asserting that symlink is a file'
        );
        $this->assertFalse(
            $sftp->is_dir('symlink'),
            'Failed asserting that symlink is not a directory'
        );

        return $sftp;
    }

    /**
     * @depends testLinkFile
     */
    public function testReadlink($sftp)
    {
        $this->assertInternalType(
            'string',
            $sftp->readlink('symlink'),
            'Failed asserting that a symlink\'s target could be read'
        );

        return $sftp;
    }

    /**
     * @depends testReadlink
     * @group github716
     */
    public function testStatOnCWD($sftp)
    {
        $stat = $sftp->stat('.');
        $this->assertInternalType(
            'array',
            $stat,
            'Failed asserting that stat on . returns an array'
        );
        $lstat = $sftp->lstat('.');
        $this->assertInternalType(
            'array',
            $lstat,
            'Failed asserting that lstat on . returns an array'
        );

        return $sftp;
    }

    /**
     * on older versions this would result in a fatal error
     * @depends testStatOnCWD
     * @group github402
     */
    public function testStatcacheFix($sftp)
    {
        // Name used for both directory and file.
        $name = 'stattestdir';
        $this->assertTrue($sftp->mkdir($name));
        $this->assertTrue($sftp->is_dir($name));
        $this->assertTrue($sftp->chdir($name));
        $this->assertStringEndsWith(self::$scratchDir . '/' . $name, $sftp->pwd());
        $this->assertFalse($sftp->file_exists($name));
        $this->assertTrue($sftp->touch($name));
        $this->assertTrue($sftp->is_file($name));
        $this->assertTrue($sftp->chdir('..'));
        $this->assertStringEndsWith(self::$scratchDir, $sftp->pwd());
        $this->assertTrue($sftp->is_dir($name));
        $this->assertTrue($sftp->is_file("$name/$name"));
        $this->assertTrue($sftp->delete($name, true));

        return $sftp;
    }

    /**
     * @depends testStatcacheFix
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
    public function testTruncateLargeFile($sftp)
    {
        $filesize = (4 * 1024 + 16) * 1024 * 1024;
        $filename = 'file-large-from-truncate-4112MiB.txt';
        $this->assertTrue($sftp->touch($filename));
        $this->assertTrue($sftp->truncate($filename, $filesize));
        $this->assertSame($filesize, $sftp->size($filename));

        return $sftp;
    }

    /**
     * @depends testTruncateLargeFile
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

        return $sftp;
    }

    /**
     * @depends testRmDirScratchNonexistent
     * @group github706
     */
    public function testDeleteEmptyDir($sftp)
    {
        $this->assertTrue(
            $sftp->mkdir(self::$scratchDir),
            'Failed asserting that scratch directory could ' .
            'be created.'
        );
        $this->assertInternalType(
            'array',
            $sftp->stat(self::$scratchDir),
            'Failed asserting that stat on an existant empty directory returns an array'
        );
        $this->assertTrue(
            $sftp->delete(self::$scratchDir),
            'Failed asserting that empty scratch directory could ' .
            'be deleted using recursive delete().'
        );
        $this->assertFalse(
            $sftp->stat(self::$scratchDir),
            'Failed asserting that stat on a deleted directory returns false'
        );

        return $sftp;
    }

    /**
     * @depends testDeleteEmptyDir
     * @group github735
     */
    public function testStatVsLstat($sftp)
    {
        $this->assertTrue($sftp->mkdir(self::$scratchDir));
        $this->assertTrue($sftp->chdir(self::$scratchDir));
        $this->assertTrue($sftp->put('text.txt', 'zzzzz'));
        $this->assertTrue($sftp->symlink('text.txt', 'link.txt'));
        $this->assertTrue($sftp->mkdir('subdir'));
        $this->assertTrue($sftp->symlink('subdir', 'linkdir'));

        $sftp->clearStatCache();

        // pre-populate the stat cache
        $sftp->nlist();

        $stat = $sftp->stat('link.txt');
        $this->assertSame($stat['type'], NET_SFTP_TYPE_REGULAR);
        $stat = $sftp->lstat('link.txt');
        $this->assertSame($stat['type'], NET_SFTP_TYPE_SYMLINK);

        $stat = $sftp->stat('linkdir');
        $this->assertSame($stat['type'], NET_SFTP_TYPE_DIRECTORY);
        $stat = $sftp->lstat('link.txt');
        $this->assertSame($stat['type'], NET_SFTP_TYPE_SYMLINK);

        $sftp->disableStatCache();

        $sftp->nlist();

        $stat = $sftp->stat('link.txt');
        $this->assertSame($stat['type'], NET_SFTP_TYPE_REGULAR);
        $stat = $sftp->lstat('link.txt');
        $this->assertSame($stat['type'], NET_SFTP_TYPE_SYMLINK);

        $stat = $sftp->stat('linkdir');
        $this->assertSame($stat['type'], NET_SFTP_TYPE_DIRECTORY);
        $stat = $sftp->lstat('link.txt');
        $this->assertSame($stat['type'], NET_SFTP_TYPE_SYMLINK);

        $sftp->enableStatCache();
    }
}
