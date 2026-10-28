<?php

namespace phpseclib3\Tests\Unit\Net;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Exception\ConnectionClosedException;
use phpseclib3\Net\SFTP;
use phpseclib3\Net\SSH2;
use phpseclib3\Tests\PhpseclibTestCase;

class SFTPUnitTest extends PhpseclibTestCase
{
    public function testRecursiveRawlist()
    {
        $sftp = new FakeSFTP();

        $list = $sftp->rawlist('.', true);

        $this->assertSame(['.', '..', 'subdir', 'file.txt'], array_keys($list));
        $this->assertSame(['.', 'leaf.txt'], array_keys($list['subdir']));
    }

    public function testRawlistAfterInterruptedRecursiveRawlist()
    {
        $sftp = new FakeSFTP();
        $sftp->interruptListingOf = '/home/test/subdir';
        try {
            $sftp->rawlist('.', true);
        } catch (ConnectionClosedException $e) {
        }
        $this->assertTrue(isset($e), 'Failed asserting that the recursive listing was interrupted');

        $sftp = new FakeSFTP();
        $this->assertArrayHasKey(
            '..',
            $sftp->rawlist('.', true),
            'Failed asserting that an interrupted recursive rawlist() does not affect later ones'
        );
    }
}

/**
 * Serves a small directory tree from memory instead of a server, by answering SFTP requests on the SSH channel:
 *
 * /home/test/file.txt
 * /home/test/subdir/leaf.txt
 */
class FakeSFTP extends SFTP
{
    /**
     * Directory whose listing fails because the connection is lost
     *
     * @var string
     */
    public $interruptListingOf;

    /**
     * SFTP packets waiting to be read
     *
     * @var string[]
     */
    private $responses = [];

    /**
     * Handles whose directory entries have been sent
     *
     * @var true[]
     */
    private $listed = [];

    public function __construct()
    {
        parent::__construct('localhost');

        // what logging in and starting the SFTP subsystem would have set up
        $this->bitmap = SSH2::MASK_LOGIN;
        $init = \Closure::bind(function () {
            $this->pwd = '/home/test';
            $this->version = 3;
        }, $this, SFTP::class);
        $init();
    }

    protected function send_channel_packet($client_channel, $data)
    {
        // without request ids, an SFTP packet is its length, its type and its payload. each request sent here
        // carries one string: the directory, or its handle, which is the directory too
        $type = ord($data[4]);
        $payload = substr($data, 5);
        list($dir) = Strings::unpackSSH2('s', $payload);
        switch ($type) {
            case NET_SFTP_OPENDIR:
                if ($dir === $this->interruptListingOf) {
                    throw new ConnectionClosedException("Connection lost while listing $dir");
                }
                $this->respond(NET_SFTP_HANDLE, Strings::packSSH2('s', $dir));
                break;
            case NET_SFTP_READDIR:
                if (isset($this->listed[$dir])) {
                    $this->respond(NET_SFTP_STATUS, pack('N', NET_SFTP_STATUS_EOF));
                    break;
                }
                $this->listed[$dir] = true;
                $entries = $dir == '/home/test' ? ['.', '..', 'subdir', 'file.txt'] : ['.', '..', 'leaf.txt'];
                $names = pack('N', count($entries));
                foreach ($entries as $entry) {
                    // filename, longname and attributes with just the permissions, which give the file type
                    $mode = substr($entry, -4) == '.txt' ? 0100644 : 040755;
                    $names .= Strings::packSSH2('ssNN', $entry, $entry, NET_SFTP_ATTR_PERMISSIONS, $mode);
                }
                $this->respond(NET_SFTP_NAME, $names);
                break;
            case NET_SFTP_CLOSE:
                $this->respond(NET_SFTP_STATUS, pack('N', NET_SFTP_STATUS_OK));
                break;
            default:
                throw new \UnexpectedValueException("Unexpected SFTP packet type $type");
        }
    }

    protected function get_channel_packet($client_channel, $skip_extended = false)
    {
        if (!count($this->responses)) {
            throw new \UnexpectedValueException('No SFTP packet to read');
        }
        return array_shift($this->responses);
    }

    /**
     * @param int $type
     * @param string $data
     */
    private function respond($type, $data)
    {
        $this->responses[] = pack('NCa*', strlen($data) + 1, $type, $data);
    }
}
