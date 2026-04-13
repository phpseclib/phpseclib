<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Functional\Net;

use phpseclib4\Net\SFTP;
use phpseclib4\Net\SFTP\FileType;
use phpseclib4\Tests\PhpseclibFunctionalTestCase;

class SFTPUserStoryTest extends PhpseclibFunctionalTestCase
{
    /**
     * @var string
     */
    protected static $scratchDir;
    protected static $exampleData;
    protected static $exampleDataLength;
    protected static $buffer;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        self::$scratchDir = uniqid('phpseclib-sftp-scratch-');

        self::$exampleData = str_repeat('abcde12345', 1000);
        self::$exampleDataLength = 10000;
    }

    public function testConstructor(): SFTP
    {
        $sftp = new SFTP($this->getEnv('SSH_HOSTNAME'));

        $this->assertIsObject(
            $sftp,
            'Could not construct NET_SFTP object.'
        );

        return $sftp;
    }

    /**
     * @depends testConstructor
     */
    public function testPasswordLogin(SFTP $sftp)
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
    public function testPwdHome(SFTP $sftp)
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
    public function testMkDirScratch(SFTP $sftp)
    {
        $dirname = self::$scratchDir;

        $sftp->mkdir($dirname);
        try {
            $sftp->mkdir($dirname);
            $this->assertTrue(
                false,
                "Failed asserting that a new scratch directory $dirname could " .
                'not be created (because it already exists).'
            );
        } catch (\Exception) {
        }

        return $sftp;
    }

    /**
     * @depends testMkDirScratch
     */
    public function testChDirScratch(SFTP $sftp)
    {
        $sftp->chdir(self::$scratchDir);

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
    public function testStatOnDir(SFTP $sftp)
    {
        $this->assertNotSame(
            [],
            $sftp->stat('.'),
            'Failed asserting that the cwd has a non-empty stat.'
        );

        return $sftp;
    }

    /**
     * @depends testStatOnDir
     */
    public function testPutSizeGetFile(SFTP $sftp)
    {
        $sftp->put('file1.txt', self::$exampleData);

        $this->assertSame(
            self::$exampleDataLength,
            $sftp->filesize('file1.txt'),
            'Failed asserting that put example data has the expected length'
        );

        $this->assertSame(
            self::$exampleData,
            $sftp->get('file1.txt'),
            'Failed asserting that get() returns expected example data.'
        );

        $sftp->put('file1.txt', 'xxx', SFTP::RESUME);

        $this->assertSame(
            self::$exampleDataLength + 3,
            $sftp->filesize('file1.txt'),
            'Failed asserting that put example data has the expected length'
        );

        $this->assertSame(
            self::$exampleData . 'xxx',
            $sftp->get('file1.txt'),
            'Failed asserting that get() returns expected example data.'
        );

        return $sftp;
    }

    /**
     * @depends testStatOnDir
     */
    public function testPutSizeGetFileCallback(SFTP $sftp)
    {
        self::$buffer = self::$exampleData;
        $closure = function ($length) {
            $r = substr(self::$buffer, 0, $length);
            self::$buffer = substr(self::$buffer, $length);
            if (strlen($r)) {
                return $r;
            }
            return null;
        };
        $sftp->put('file1.txt', $closure, $sftp::SOURCE_CALLBACK);

        $this->assertSame(
            self::$exampleDataLength,
            $sftp->filesize('file1.txt'),
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
    public function testTouch(SFTP $sftp)
    {
        $sftp->touch('file2.txt');

        $this->assertTrue(
            $sftp->file_exists('file2.txt'),
            'Failed asserting that touch()\'d file exists'
        );

        return $sftp;
    }

    /**
     * @depends testTouch
     */
    public function testTruncate(SFTP $sftp)
    {
        $sftp->touch('file3.txt');

        $sftp->truncate('file3.txt', 1024 * 1024);

        $this->assertSame(
            1024 * 1024,
            $sftp->filesize('file3.txt'),
            'Failed asserting that truncate()\'d file has the expected length'
        );

        return $sftp;
    }

    /**
     * @depends testTruncate
     * @group github850
     */
    public function testChModOnFile(SFTP $sftp)
    {
        $sftp->chmod('file1.txt', 0o755);

        return $sftp;
    }

    /**
     * @depends testChModOnFile
     */
    public function testChDirOnFile(SFTP $sftp)
    {
        try {
            $sftp->chdir('file1.txt');
            $this->assertTrue(
                false,
                'Failed to assert that the cwd cannot be changed to a file'
            );
        } catch (\Exception) {
        }

        return $sftp;
    }

    /**
     * @depends testChDirOnFile
     */
    public function testFileExistsIsFileIsDirFile(SFTP $sftp)
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
    public function testFileExistsIsFileIsDirFileNonexistent(SFTP $sftp)
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
    public function testSortOrder(SFTP $sftp)
    {
        $sftp->mkdir('temp');

        $sftp->setListOrder('filename', SORT_DESC);

        $list = $sftp->nlist();
        $expected = ['.', '..', 'temp', 'file3.txt', 'file2.txt', 'file1.txt'];

        $this->assertSame(
            $list,
            $expected,
            'Failed asserting that list sorted correctly.'
        );

        $sftp->setListOrder('filename', SORT_ASC);

        $list = $sftp->nlist();
        $expected = ['.', '..', 'temp', 'file1.txt', 'file2.txt', 'file3.txt'];

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
                $cur_size = $sftp->filesize($file);
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
    public function testResourceXfer(SFTP $sftp)
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
    public function testSymlink(SFTP $sftp)
    {
        $sftp->symlink('file3.txt', 'symlink');

        return $sftp;
    }

    /**
     * @depends testSymlink
     */
    public function testStatLstatCache(SFTP $sftp)
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
    public function testLinkFile(SFTP $sftp)
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
    public function testReadlink(SFTP $sftp)
    {
        $this->assertIsString(
            $sftp->readlink('symlink'),
            'Failed asserting that a symlink\'s target could be read'
        );

        return $sftp;
    }

    /**
     * @depends testReadlink
     * @group github716
     */
    public function testStatOnCWD(SFTP $sftp)
    {
        $stat = $sftp->stat('.');
        $this->assertIsArray(
            $stat,
            'Failed asserting that stat on . returns an array'
        );
        $lstat = $sftp->lstat('.');
        $this->assertIsArray(
            $lstat,
            'Failed asserting that lstat on . returns an array'
        );

        return $sftp;
    }

    /**
     * on older versions this would result in a fatal error
     *
     * @depends testStatOnCWD
     * @group github402
     */
    public function testStatcacheFix(SFTP $sftp)
    {
        // Name used for both directory and file.
        $name = 'stattestdir';
        $sftp->mkdir($name);
        $this->assertTrue($sftp->is_dir($name));
        $sftp->chdir($name);
        $this->assertStringEndsWith(self::$scratchDir . '/' . $name, $sftp->pwd());
        $this->assertFalse($sftp->file_exists($name));
        $sftp->touch($name);
        $this->assertTrue($sftp->is_file($name));
        $sftp->chdir('..');
        $this->assertStringEndsWith(self::$scratchDir, $sftp->pwd());
        $this->assertTrue($sftp->is_dir($name));
        $this->assertTrue($sftp->is_file("$name/$name"));
        $sftp->delete($name, true);

        return $sftp;
    }

    /**
     * @depends testStatcacheFix
     */
    public function testChDirUpHome(SFTP $sftp)
    {
        $sftp->chdir('../');

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
    public function testFileExistsIsFileIsDirDir(SFTP $sftp)
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
    public function testTruncateLargeFile(SFTP $sftp)
    {
        $filesize = (4 * 1024 + 16) * 1024 * 1024;
        $filename = 'file-large-from-truncate-4112MiB.txt';
        $sftp->touch($filename);
        $sftp->truncate($filename, $filesize);
        $this->assertSame($filesize, $sftp->filesize($filename));

        return $sftp;
    }

    /**
     * @depends testTruncateLargeFile
     */
    public function testRmDirScratch(SFTP $sftp)
    {
        $sftp->rmdir(self::$scratchDir);

        return $sftp;
    }

    /**
     * @depends testRmDirScratch
     */
    public function testDeleteRecursiveScratch(SFTP $sftp)
    {
        $sftp->delete(self::$scratchDir);

        return $sftp;
    }

    /**
     * @depends testDeleteRecursiveScratch
     */
    public function testRmDirScratchNonexistent(SFTP $sftp)
    {
        $sftp->rmdir(self::$scratchDir);

        return $sftp;
    }

    /**
     * @depends testRmDirScratchNonexistent
     * @group github706
     */
    public function testDeleteEmptyDir(SFTP $sftp)
    {
        $sftp->mkdir(self::$scratchDir);
        $this->assertIsArray(
            $sftp->stat(self::$scratchDir),
            'Failed asserting that stat on an existent empty directory returns an array'
        );
        $sftp->delete(self::$scratchDir);
        try {
            $sftp->stat(self::$scratchDir);
            $this->assertTrue(
                false,
                'Failed asserting that stat on a deleted directory returns false'
            );
        } catch (\Exception) {
        }

        try {
            $sftp->delete(self::$scratchDir);
            $this->assertTrue(
                false,
                'Failed asserting that non-existent directory could not ' .
                'be deleted using recursive delete().'
            );
        } catch (\Exception) {
        }

        return $sftp;
    }

    /**
     * @depends testDeleteEmptyDir
     * @group github735
     */
    public function testStatVsLstat(SFTP $sftp)
    {
        $sftp->mkdir(self::$scratchDir);
        $sftp->chdir(self::$scratchDir);
        $sftp->put('text.txt', 'zzzzz');
        $sftp->symlink('text.txt', 'link.txt');
        $sftp->mkdir('subdir');
        $sftp->symlink('subdir', 'linkdir');

        $sftp->clearStatCache();

        // pre-populate the stat cache
        $sftp->nlist();

        $stat = $sftp->stat('link.txt');
        $this->assertSame($stat['type'], FileType::REGULAR);
        $stat = $sftp->lstat('link.txt');
        $this->assertSame($stat['type'], FileType::SYMLINK);

        $stat = $sftp->stat('linkdir');
        $this->assertSame($stat['type'], FileType::DIRECTORY);
        $stat = $sftp->lstat('link.txt');
        $this->assertSame($stat['type'], FileType::SYMLINK);

        $sftp->disableStatCache();

        $sftp->nlist();

        $stat = $sftp->stat('link.txt');
        $this->assertSame($stat['type'], FileType::REGULAR);
        $stat = $sftp->lstat('link.txt');
        $this->assertSame($stat['type'], FileType::SYMLINK);

        $stat = $sftp->stat('linkdir');
        $this->assertSame($stat['type'], FileType::DIRECTORY);
        $stat = $sftp->lstat('link.txt');
        $this->assertSame($stat['type'], FileType::SYMLINK);

        $sftp->enableStatCache();

        return $sftp;
    }

    /**
     * @depends testStatVsLstat
     * @group github830
     */
    public function testUploadOffsets(SFTP $sftp)
    {
        $sftp->put('offset.txt', 'res.txt', SFTP::SOURCE_LOCAL_FILE, 0, 10);
        $this->assertSame(
            substr(self::$exampleData, 10),
            $sftp->get('offset.txt'),
            'Failed asserting that portions of a file could be uploaded.'
        );

        $sftp->put('offset.txt', 'res.txt', SFTP::SOURCE_LOCAL_FILE, self::$exampleDataLength - 100);
        $this->assertSame(
            substr(self::$exampleData, 10, -90) . self::$exampleData,
            $sftp->get('offset.txt'),
            'Failed asserting that you could upload into the middle of a file.'
        );

        return $sftp;
    }

    /**
     * @depends testUploadOffsets
     */
    public function testReadableWritable(SFTP $sftp)
    {
        $sftp->chmod(0, 'offset.txt');
        $this->assertFalse($sftp->is_writable('offset.txt'));
        $this->assertFalse($sftp->is_writeable('offset.txt'));
        $this->assertFalse($sftp->is_readable('offset.txt'));

        $sftp->chmod(0o777, 'offset.txt');
        $this->assertTrue($sftp->is_writable('offset.txt'));
        $this->assertTrue($sftp->is_writeable('offset.txt'));
        $this->assertTrue($sftp->is_readable('offset.txt'));

        $this->assertFalse($sftp->is_writable('nonexistantfile.ext'));
        $this->assertFalse($sftp->is_writeable('nonexistantfile.ext'));
        $this->assertFalse($sftp->is_readable('nonexistantfile.ext'));

        return $sftp;
    }

    /**
     * @depends testReadableWritable
     * @group github999
     */
    public function testExecNlist(SFTP $sftp)
    {
        $sftp->enablePTY();
        $sftp->exec('ping google.com -c 5');
        sleep(5);
        $sftp->nlist();

        $this->assertTrue(true);

        return $sftp;
    }

    /**
     * @depends testExecNlist
     */
    public function testRawlistDisabledStatCache(SFTP $sftp)
    {
        $sftp->mkdir(self::$scratchDir);
        $sftp->chdir(self::$scratchDir);
        $sftp->put('text.txt', 'zzzzz');
        $sftp->mkdir('subdir');
        $sftp->chdir('subdir');
        $sftp->put('leaf.txt', 'yyyyy');
        $sftp->chdir('../../');

        $list_cache_enabled = $sftp->rawlist('.', true);

        $sftp->clearStatCache();

        $sftp->disableStatCache();

        $list_cache_disabled = $sftp->rawlist('.', true);

        $this->assertEquals(
            $list_cache_enabled,
            $list_cache_disabled,
            'The files should be the same regardless of stat cache'
        );

        return $sftp;
    }

    /**
     * @depends testRawlistDisabledStatCache
     */
    public function testRawlistCallback(SFTP $sftp)
    {
        $files = [];
        $callback = function ($dir, $filename, $attributes) use (&$files): void {
            $files[] = $filename;
        };

        $sftp->rawlist(self::$scratchDir, true, $callback);

        $this->assertContains('text.txt', $files);
        $this->assertContains('subdir', $files);
        $this->assertContains('leaf.txt', $files);

        return $sftp;
    }

    /**
     * @depends testRawlistCallback
     */
    public function testChownChgrp(SFTP $sftp)
    {
        $stat = $sftp->stat(self::$scratchDir);
        $sftp->chown(self::$scratchDir, $stat['uid']);
        $sftp->chgrp(self::$scratchDir, $stat['gid']);

        $sftp->clearStatCache();
        $stat2 = $sftp->stat(self::$scratchDir);
        $this->assertSame($stat['uid'], $stat2['uid']);
        $this->assertSame($stat['gid'], $stat2['gid']);

        return $sftp;
    }

    /**
     * @depends testChownChgrp
     * @group github1934
     */
    public function testCallableGetWithLength(SFTP $sftp): SFTP
    {
        $sftp->put('test.txt', 'zzzzz');
        $sftp->get('test.txt', function ($data): void {
            $this->assertSame('z', $data);
        }, 0, 1);
        return $sftp;
    }


    /**
     * @depends testPasswordLogin
     */
    public function testStatVfs(SFTP $sftp): void
    {
        $sftp->put('test.txt', 'aaaaa');
        $stat = $sftp->statvfs('test.txt');

        $this->assertArrayHasKey('bsize', $stat);
        $this->assertArrayHasKey('frsize', $stat);
        $this->assertArrayHasKey('blocks', $stat);
        $this->assertArrayHasKey('bfree', $stat);
        $this->assertArrayHasKey('bavail', $stat);
        $this->assertArrayHasKey('files', $stat);
        $this->assertArrayHasKey('ffree', $stat);
        $this->assertArrayHasKey('favail', $stat);
        $this->assertArrayHasKey('fsid', $stat);
        $this->assertArrayHasKey('flag', $stat);
        $this->assertArrayHasKey('namemax', $stat);

        $this->assertSame(255, $stat['namemax']);
    }

    /**
     * @depends testPasswordLogin
     */
    public function testPosixRename(SFTP $sftp): void
    {
        $sftp->put('test1.txt', 'aaaaa');
        $sftp->put('test2.txt', 'bbbbb');

        $sftp->posix_rename('test1.txt', 'test2.txt');
        $this->assertSame('aaaaa', $sftp->get('test2.txt'));
    }
}
