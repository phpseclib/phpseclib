<?php

use phpseclib\Net\SFTP;

class Unit_Net_SFTPUnitTest extends PhpseclibTestCase
{
    public function testRecursiveRawlist()
    {
        $sftp = new SFTPUnitTest_FakeSFTP();

        $list = $sftp->rawlist('.', true);

        $this->assertSame(array('.', '..', 'subdir', 'file.txt'), array_keys($list));
        $this->assertSame(array('.', 'leaf.txt'), array_keys($list['subdir']));
    }

    public function testRawlistAfterInterruptedRecursiveRawlist()
    {
        $sftp = new SFTPUnitTest_FakeSFTP();
        $sftp->interruptListingOf = './subdir';
        try {
            $sftp->rawlist('.', true);
        } catch (SFTPUnitTest_ListingInterrupted $e) {
        }
        $this->assertTrue(isset($e), 'Failed asserting that the recursive listing was interrupted');

        $sftp = new SFTPUnitTest_FakeSFTP();
        $this->assertArrayHasKey(
            '..',
            $sftp->rawlist('.', true),
            'Failed asserting that an interrupted recursive rawlist() does not affect later ones'
        );
    }
}

class SFTPUnitTest_ListingInterrupted extends Exception
{
}

/**
 * Serves a small directory tree from memory instead of a server:
 *
 * ./file.txt
 * ./subdir/leaf.txt
 */
class SFTPUnitTest_FakeSFTP extends SFTP
{
    /**
     * Directory whose listing fails, eg. because the connection is lost while it's being read
     */
    var $interruptListingOf;

    function __construct()
    {
        parent::__construct('localhost');
        $this->disableStatCache();
    }

    function _list($dir, $raw = true)
    {
        if ($dir === $this->interruptListingOf) {
            throw new SFTPUnitTest_ListingInterrupted("Connection lost while listing $dir");
        }

        $entries = $dir == '.' ?
            array('.', '..', 'subdir', 'file.txt') :
            array('.', '..', 'leaf.txt');
        $files = array();
        foreach ($entries as $entry) {
            $files[$entry] = array('filename' => $entry);
        }
        return $files;
    }

    function lstat($filename)
    {
        return array('type' => basename($filename) == 'subdir' ? NET_SFTP_TYPE_DIRECTORY : NET_SFTP_TYPE_REGULAR);
    }
}
