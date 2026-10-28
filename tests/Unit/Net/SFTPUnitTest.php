<?php

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Net;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Exception\ConnectionClosedException;
use phpseclib4\Net\SFTP;
use phpseclib4\Net\SFTP\Attribute;
use phpseclib4\Net\SFTP\PacketType;
use phpseclib4\Net\SFTP\StatusCode;
use phpseclib4\Net\SSH2;
use phpseclib4\Tests\PhpseclibTestCase;

class SFTPUnitTest extends PhpseclibTestCase
{
    public function testRecursiveRawlist(): void
    {
        $sftp = self::createSFTP();

        $list = $sftp->rawlist('.', true);

        $this->assertSame(['.', '..', 'subdir', 'file.txt'], array_keys($list));
        $this->assertSame(['.', 'leaf.txt'], array_keys($list['subdir']));
    }

    public function testRawlistAfterInterruptedRecursiveRawlist(): void
    {
        $sftp = self::createSFTP('/home/test/subdir');
        try {
            $sftp->rawlist('.', true);
        } catch (ConnectionClosedException $e) {
        }
        $this->assertTrue(isset($e), 'Failed asserting that the recursive listing was interrupted');

        $sftp = self::createSFTP();
        $this->assertArrayHasKey(
            '..',
            $sftp->rawlist('.', true),
            'Failed asserting that an interrupted recursive rawlist() does not affect later ones'
        );
    }

    /**
     * Creates an SFTP connection that serves a small directory tree from memory instead of a server, by answering
     * SFTP requests on the SSH channel:
     *
     * /home/test/file.txt
     * /home/test/subdir/leaf.txt
     *
     * @param ?string $interruptListingOf Directory whose listing fails because the connection is lost
     */
    private static function createSFTP(?string $interruptListingOf = null): SFTP
    {
        return new class ($interruptListingOf) extends SFTP {
            /**
             * SFTP packets waiting to be read
             *
             * @var list<string>
             */
            private array $responses = [];

            /**
             * Handles whose directory entries have been sent
             *
             * @var array<string, true>
             */
            private array $listed = [];

            public function __construct(private ?string $interruptListingOf)
            {
                parent::__construct('localhost');

                // what logging in and starting the SFTP subsystem would have set up
                $this->bitmap = SSH2::MASK_LOGIN;
                (new \ReflectionProperty(SFTP::class, 'pwd'))->setValue($this, '/home/test');
                (new \ReflectionProperty(SFTP::class, 'version'))->setValue($this, 3);
            }

            protected function send_channel_packet(int $client_channel, string $data): void
            {
                // without request ids, an SFTP packet is its length, its type and its payload. each request sent here
                // carries one string: the directory, or its handle, which is the directory too
                $type = ord($data[4]);
                $payload = substr($data, 5);
                [$dir] = Strings::unpackSSH2('s', $payload);
                switch ($type) {
                    case PacketType::OPENDIR:
                        if ($dir === $this->interruptListingOf) {
                            throw new ConnectionClosedException("Connection lost while listing $dir");
                        }
                        $this->respond(PacketType::HANDLE, Strings::packSSH2('s', $dir));
                        break;
                    case PacketType::READDIR:
                        if (isset($this->listed[$dir])) {
                            $this->respond(PacketType::STATUS, pack('N', StatusCode::EOF));
                            break;
                        }
                        $this->listed[$dir] = true;
                        $entries = $dir == '/home/test' ? ['.', '..', 'subdir', 'file.txt'] : ['.', '..', 'leaf.txt'];
                        $names = pack('N', count($entries));
                        foreach ($entries as $entry) {
                            // filename, longname and attributes with just the permissions, which give the file type
                            $mode = str_ends_with($entry, '.txt') ? 0100644 : 040755;
                            $names .= Strings::packSSH2('ssNN', $entry, $entry, Attribute::PERMISSIONS, $mode);
                        }
                        $this->respond(PacketType::NAME, $names);
                        break;
                    case PacketType::CLOSE:
                        $this->respond(PacketType::STATUS, pack('N', StatusCode::OK));
                        break;
                    default:
                        throw new \UnexpectedValueException("Unexpected SFTP packet type $type");
                }
            }

            protected function get_channel_packet(int $client_channel, bool $skip_extended = false): string|bool
            {
                if (!count($this->responses)) {
                    throw new \UnexpectedValueException('No SFTP packet to read');
                }
                return array_shift($this->responses);
            }

            private function respond(int $type, string $data): void
            {
                $this->responses[] = pack('NCa*', strlen($data) + 1, $type, $data);
            }
        };
    }
}
