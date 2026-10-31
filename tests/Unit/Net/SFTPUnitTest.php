<?php

require_once 'Net/SFTP.php';

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

    public function testRequestAfterTimeout()
    {
        $sftp = new SFTPUnitTest_SlowSFTP();
        $this->assertSame(1, $sftp->filesize('/fast.txt'));

        $this->assertFalse(@$sftp->filesize('/slow.txt'));
        $this->assertTrue($sftp->isTimeout());
        $this->assertFalse($sftp->isConnected());

        $this->assertFalse(
            $sftp->filesize('/fast.txt'),
            'Failed asserting that the late reply about slow.txt is not taken as the reply about fast.txt'
        );
    }
}

class SFTPUnitTest_ListingInterrupted extends Exception
{
}

/**
 * Answers stat requests from memory instead of a server
 *
 * Replies about /slow.txt only arrive once the next request has been sent, as if the server took too long with them.
 */
class SFTPUnitTest_SlowSFTP extends Net_SFTP
{
    /**
     * File sizes by path
     */
    var $sizes = array('/fast.txt' => 1, '/slow.txt' => 2);

    /**
     * SFTP packets waiting to be read
     */
    var $responses = array();

    /**
     * The reply about /slow.txt that hasn't arrived yet
     */
    var $late;

    function __construct()
    {
        parent::__construct(fopen('php://memory', 'r'));

        // what connecting, logging in and starting the SFTP subsystem would have set up
        $this->bitmap = NET_SSH2_MASK_CONSTRUCTOR | NET_SSH2_MASK_CONNECTED | NET_SSH2_MASK_LOGIN;
        $this->channel_status[NET_SFTP_CHANNEL] = NET_SSH2_MSG_CHANNEL_DATA;
        $this->pwd = '/';
        $this->version = 3;
        $this->disableStatCache();
    }

    function _send_binary_packet($data, $logged = null)
    {
        // the disconnect message
        return true;
    }

    function _send_channel_packet($client_channel, $data)
    {
        if (isset($this->late)) {
            $this->responses[] = $this->late;
            $this->late = null;
        }

        // without request ids, an SFTP packet is its length, its type and its payload, which for the stat requests
        // sent here is the path
        extract(unpack('Nlength', substr($data, 5, 4)));
        $path = substr($data, 9, $length);
        // the attributes' flags, the size as a 64-bit integer and the permissions, which give the file type
        $attrs = pack('N4', NET_SFTP_ATTR_SIZE | NET_SFTP_ATTR_PERMISSIONS, 0, $this->sizes[$path], 0100644);
        $response = pack('NCa*', strlen($attrs) + 1, NET_SFTP_ATTRS, $attrs);
        if ($path == '/slow.txt') {
            $this->late = $response;
        } else {
            $this->responses[] = $response;
        }
        return true;
    }

    function _get_channel_packet($client_channel, $skip_extended = false)
    {
        if (!count($this->responses)) {
            // what Net_SSH2 does when the timeout runs out
            $this->is_timeout = true;
            return true;
        }
        return array_shift($this->responses);
    }
}

/**
 * Serves a small directory tree from memory instead of a server:
 *
 * ./file.txt
 * ./subdir/leaf.txt
 */
class SFTPUnitTest_FakeSFTP extends Net_SFTP
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
