<?php

/**
 * Pure-PHP implementation of SFTP.
 *
 * PHP version 5
 *
 * Supports SFTPv2/3/4/5/6. Defaults to v3.
 *
 * The API for this library is modeled after the API from PHP's {@link http://php.net/book.ftp FTP extension}.
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $sftp = new \phpseclib3\Net\SFTP('www.domain.tld');
 *    if (!$sftp->login('username', 'password')) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $sftp->pwd() . "\r\n";
 *    $sftp->put('filename.ext', 'hello, world!');
 *    print_r($sftp->nlist());
 * ?>
 * </code>
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Net;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Exception\BadFunctionCallException;
use phpseclib3\Exception\FileNotFoundException;
use phpseclib3\Exception\RuntimeException;
use phpseclib3\Exception\UnexpectedValueException;
use phpseclib3\Net\SFTP\Attribute;
use phpseclib3\Net\SFTP\FileType;
use phpseclib3\Net\SFTP\OpenFlag;
use phpseclib3\Net\SFTP\OpenFlag5;
use phpseclib3\Net\SFTP\PacketType as SFTPPacketType;
use phpseclib3\Net\SFTP\StatusCode;
use phpseclib3\Net\SSH2\MessageType as SSH2MessageType;

/**
 * Pure-PHP implementations of SFTP.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class SFTP extends SSH2
{
    /**
     * SFTP channel constant
     *
     * \phpseclib3\Net\SSH2::exec() uses 0 and \phpseclib3\Net\SSH2::read() / \phpseclib3\Net\SSH2::write() use 1.
     *
     * @see \phpseclib3\Net\SSH2::send_channel_packet()
     * @see \phpseclib3\Net\SSH2::get_channel_packet()
     */
    public const CHANNEL = 0x100;

    /**
     * Reads data from a local file.
     *
     * @see \phpseclib3\Net\SFTP::put()
     */
    public const SOURCE_LOCAL_FILE = 1;
    /**
     * Reads data from a string.
     *
     * @see \phpseclib3\Net\SFTP::put()
     */
    // this value isn't really used anymore but i'm keeping it reserved for historical reasons
    public const SOURCE_STRING = 2;
    /**
     * Reads data from callback:
     * function callback($length) returns string to proceed, null for EOF
     *
     * @see \phpseclib3\Net\SFTP::put()
     */
    public const SOURCE_CALLBACK = 16;
    /**
     * Resumes an upload
     *
     * @see \phpseclib3\Net\SFTP::put()
     */
    public const RESUME = 4;
    /**
     * Append a local file to an already existing remote file
     *
     * @see \phpseclib3\Net\SFTP::put()
     */
    public const RESUME_START = 8;

    /**
     * The Request ID
     *
     * The request ID exists in the off chance that a packet is sent out-of-order.  Of course, this library doesn't support
     * concurrent actions, so it's somewhat academic, here.
     *
     * @see self::_send_sftp_packet()
     */
    private bool $use_request_id = false;

    /**
     * The Packet Type
     *
     * The request ID exists in the off chance that a packet is sent out-of-order.  Of course, this library doesn't support
     * concurrent actions, so it's somewhat academic, here.
     *
     * @see self::_get_sftp_packet()
     */
    private int $packet_type = -1;

    /**
     * Packet Buffer
     *
     * @see self::_get_sftp_packet()
     */
    private string $packet_buffer = '';

    /**
     * Extensions supported by the server
     *
     * @see self::_initChannel()
     */
    private array $extensions = [];

    /**
     * Server SFTP version
     *
     * @see self::_initChannel()
     */
    private int $version;

    /**
     * Default Server SFTP version
     *
     * @see self::_initChannel()
     */
    private int $defaultVersion;

    /**
     * Preferred SFTP version
     *
     * @see self::_initChannel()
     */
    private int $preferredVersion = 3;

    /**
     * Current working directory
     *
     * @see self::realpath()
     * @see self::chdir()
     */
    private string|bool $pwd = false;

    /**
     * Packet Type Log
     *
     * @see self::getLog()
     */
    private array $packet_type_log = [];

    /**
     * Packet Log
     *
     * @see self::getLog()
     */
    private array $packet_log = [];

    /**
     * Real-time log file pointer
     *
     * @see self::_append_log()
     * @var resource|closed-resource
     */
    private $realtime_log_file;

    /**
     * Real-time log file size
     *
     * @see self::_append_log()
     */
    private int $realtime_log_size;

    /**
     * Real-time log file wrap boolean
     *
     * @see self::_append_log()
     */
    private bool $realtime_log_wrap;

    /**
     * Current log size
     *
     * Should never exceed self::LOG_MAX_SIZE
     */
    private int $log_size;

    /**
     * Error information
     *
     * @see self::getSFTPErrors()
     * @see self::getLastSFTPError()
     */
    private array $sftp_errors = [];

    /**
     * Stat Cache
     *
     * Rather than always having to open a directory and close it immediately there after to see if a file is a directory
     * we'll cache the results.
     *
     * @see self::_update_stat_cache()
     * @see self::_remove_from_stat_cache()
     * @see self::_query_stat_cache()
     */
    private array $stat_cache = [];

    /**
     * Max SFTP Packet Size
     *
     * @see self::__construct()
     * @see self::get()
     */
    private int $max_sftp_packet;

    /**
     * Stat Cache Flag
     *
     * @see self::disableStatCache()
     * @see self::enableStatCache()
     */
    private bool $use_stat_cache = true;

    /**
     * Sort Options
     *
     * @see self::_comparator()
     * @see self::setListOrder()
     */
    private array $sortOptions = [];

    /**
     * Canonicalization Flag
     *
     * Determines whether or not paths should be canonicalized before being
     * passed on to the remote server.
     *
     * @see self::enablePathCanonicalization()
     * @see self::disablePathCanonicalization()
     * @see self::realpath()
     */
    private bool $canonicalize_paths = true;

    /**
     * Request Buffers
     *
     * @see self::_get_sftp_packet()
     */
    private array $requestBuffer = [];

    /**
     * Preserve timestamps on file downloads / uploads
     *
     * @see self::get()
     * @see self::put()
     */
    private bool $preserveTime = false;

    /**
     * Arbitrary Length Packets Flag
     *
     * Determines whether or not packets of any length should be allowed,
     * in cases where the server chooses the packet length (such as
     * directory listings). By default, packets are only allowed to be
     * 256 * 1024 bytes (SFTP_MAX_MSG_LENGTH from OpenSSH's sftp-common.h)
     *
     * @see self::enableArbitraryLengthPackets()
     * @see self::_get_sftp_packet()
     */
    private bool $allow_arbitrary_length_packets = false;

    /**
     * Was the last packet due to the channels being closed or not?
     *
     * @see self::get()
     * @see self::get_sftp_packet()
     */
    private bool $channel_close = false;

    /**
     * Has the SFTP channel been partially negotiated?
     */
    private bool $partial_init = false;

    private int $queueSize = 32;
    private int $uploadQueueSize = 1024;

    /**
     * Default Constructor.
     *
     * Connects to an SFTP server
     */
    public function __construct($host, int $port = 22, int $timeout = 10)
    {
        parent::__construct($host, $port, $timeout);

        $this->max_sftp_packet = 1 << 15;

        if (defined('NET_SFTP_QUEUE_SIZE')) {
            $this->queueSize = NET_SFTP_QUEUE_SIZE;
        }
        if (defined('NET_SFTP_UPLOAD_QUEUE_SIZE')) {
            $this->uploadQueueSize = NET_SFTP_UPLOAD_QUEUE_SIZE;
        }
    }

    /**
     * Check a few things before SFTP functions are called
     */
    private function precheck(): bool
    {
        if (!($this->bitmap & SSH2::MASK_LOGIN)) {
            return false;
        }

        if ($this->pwd === false) {
            return $this->init_sftp_connection();
        }

        return true;
    }

    /**
     * Partially initialize an SFTP connection
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    private function partial_init_sftp_connection(): bool
    {
        $response = $this->open_channel(self::CHANNEL, true);
        if ($response === true && $this->isTimeout()) {
            return false;
        }

        $packet = Strings::packSSH2(
            'CNsbs',
            SSH2MessageType::CHANNEL_REQUEST,
            $this->server_channels[self::CHANNEL],
            'subsystem',
            true,
            'sftp'
        );
        $this->send_binary_packet($packet);

        $this->channel_status[self::CHANNEL] = SSH2MessageType::CHANNEL_REQUEST;

        $response = $this->get_channel_packet(self::CHANNEL, true);
        if ($response === false) {
            // from PuTTY's psftp.exe
            $command = "test -x /usr/lib/sftp-server && exec /usr/lib/sftp-server\n" .
                       "test -x /usr/local/lib/sftp-server && exec /usr/local/lib/sftp-server\n" .
                       "exec sftp-server";
            // we don't do $this->exec($command, false) because exec() operates on a different channel and plus the SSH_MSG_CHANNEL_OPEN that exec() does
            // is redundant
            $packet = Strings::packSSH2(
                'CNsCs',
                SSH2MessageType::CHANNEL_REQUEST,
                $this->server_channels[self::CHANNEL],
                'exec',
                1,
                $command
            );
            $this->send_binary_packet($packet);

            $this->channel_status[self::CHANNEL] = SSH2MessageType::CHANNEL_REQUEST;

            $response = $this->get_channel_packet(self::CHANNEL, true);
            if ($response === false) {
                return false;
            }
        } elseif ($response === true && $this->isTimeout()) {
            return false;
        }

        $this->channel_status[self::CHANNEL] = SSH2MessageType::CHANNEL_DATA;
        $this->send_sftp_packet(SFTPPacketType::INIT, "\0\0\0\3");

        $response = $this->get_sftp_packet();
        if ($this->packet_type != SFTPPacketType::VERSION) {
            throw new UnexpectedValueException('Expected PacketType::VERSION. '
                                              . 'Got packet type: ' . $this->packet_type);
        }

        $this->use_request_id = true;

        [$this->defaultVersion] = Strings::unpackSSH2('N', $response);
        while (!empty($response)) {
            [$key, $value] = Strings::unpackSSH2('ss', $response);
            $this->extensions[$key] = $value;
        }

        $this->partial_init = true;

        return true;
    }

    /**
     * (Re)initializes the SFTP channel
     */
    private function init_sftp_connection(): bool
    {
        if (!$this->partial_init && !$this->partial_init_sftp_connection()) {
            return false;
        }

        /*
         A Note on SFTPv4/5/6 support:
         <http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-5.1> states the following:

         "If the client wishes to interoperate with servers that support noncontiguous version
          numbers it SHOULD send '3'"

         Given that the server only sends its version number after the client has already done so, the above
         seems to be suggesting that v3 should be the default version.  This makes sense given that v3 is the
         most popular.

         <http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-5.5> states the following;

         "If the server did not send the "versions" extension, or the version-from-list was not included, the
          server MAY send a status response describing the failure, but MUST then close the channel without
          processing any further requests."

         So what do you do if you have a client whose initial SSH_FXP_INIT packet says it implements v3 and
         a server whose initial SSH_FXP_VERSION reply says it implements v4 and only v4?  If it only implements
         v4, the "versions" extension is likely not going to have been sent so version re-negotiation as discussed
         in draft-ietf-secsh-filexfer-13 would be quite impossible.  As such, what \phpseclib3\Net\SFTP would do is close the
         channel and reopen it with a new and updated SSH_FXP_INIT packet.
        */
        $this->version = $this->defaultVersion;
        if (isset($this->extensions['versions']) && (!$this->preferredVersion || $this->preferredVersion != $this->version)) {
            $versions = explode(',', $this->extensions['versions']);
            $supported = [6, 5, 4];
            if ($this->preferredVersion) {
                $supported = array_diff($supported, [$this->preferredVersion]);
                array_unshift($supported, $this->preferredVersion);
            }
            foreach ($supported as $ver) {
                if (in_array($ver, $versions)) {
                    if ($ver === $this->version) {
                        break;
                    }
                    $this->version = (int) $ver;
                    $packet = Strings::packSSH2('ss', 'version-select', "$ver");
                    $this->send_sftp_packet(SFTPPacketType::EXTENDED, $packet);
                    $response = $this->get_sftp_packet();
                    if ($this->packet_type != SFTPPacketType::STATUS) {
                        throw new UnexpectedValueException('Expected PacketType::STATUS. '
                            . 'Got packet type: ' . $this->packet_type);
                    }
                    [$status] = Strings::unpackSSH2('N', $response);
                    if ($status != StatusCode::OK) {
                        $this->logError($response, $status);
                        throw new UnexpectedValueException('Expected StatusCode::OK. '
                            . ' Got ' . $status);
                    }
                    break;
                }
            }
        }

        /*
         SFTPv4+ defines a 'newline' extension.  SFTPv3 seems to have unofficial support for it via 'newline@vandyke.com',
         however, I'm not sure what 'newline@vandyke.com' is supposed to do (the fact that it's unofficial means that it's
         not in the official SFTPv3 specs) and 'newline@vandyke.com' / 'newline' are likely not drop-in substitutes for
         one another due to the fact that 'newline' comes with a SSH_FXF_TEXT bitmask whereas it seems unlikely that
         'newline@vandyke.com' would.
        */
        /*
        if (isset($this->extensions['newline@vandyke.com'])) {
            $this->extensions['newline'] = $this->extensions['newline@vandyke.com'];
            unset($this->extensions['newline@vandyke.com']);
        }
        */
        if ($this->version < 2 || $this->version > 6) {
            return false;
        }

        $this->pwd = true;
        try {
            $this->pwd = $this->realpath('.');
        } catch (\UnexpectedValueException $e) {
            if (!$this->canonicalize_paths) {
                throw $e;
            }
            $this->canonicalize_paths = false;
            $this->reset_sftp();
            return $this->init_sftp_connection();
        }

        $this->update_stat_cache($this->pwd, []);

        return true;
    }

    /**
     * Disable the stat cache
     */
    public function disableStatCache(): void
    {
        $this->use_stat_cache = false;
    }

    /**
     * Enable the stat cache
     */
    public function enableStatCache(): void
    {
        $this->use_stat_cache = true;
    }

    /**
     * Clear the stat cache
     */
    public function clearStatCache(): void
    {
        $this->stat_cache = [];
    }

    /**
     * Enable path canonicalization
     */
    public function enablePathCanonicalization(): void
    {
        $this->canonicalize_paths = true;
    }

    /**
     * Disable path canonicalization
     *
     * If this is enabled then $sftp->pwd() will not return the canonicalized absolute path
     */
    public function disablePathCanonicalization(): void
    {
        $this->canonicalize_paths = false;
    }

    /**
     * Enable arbitrary length packets
     */
    public function enableArbitraryLengthPackets(): void
    {
        $this->allow_arbitrary_length_packets = true;
    }

    /**
     * Disable arbitrary length packets
     */
    public function disableArbitraryLengthPackets(): void
    {
        $this->allow_arbitrary_length_packets = false;
    }

    /**
     * Returns the current directory name
     *
     * @return string|bool
     */
    public function pwd()
    {
        if (!$this->precheck()) {
            return false;
        }

        return $this->pwd;
    }

    /**
     * Logs errors
     */
    private function logError(string $response, int $status = -1): void
    {
        if ($status == -1) {
            [$status] = Strings::unpackSSH2('N', $response);
        }

        $error = StatusCode::getConstantNameByValue($status);

        if ($this->version > 2) {
            [$message] = Strings::unpackSSH2('s', $response);
            $this->sftp_errors[] = "$error: $message";
        } else {
            $this->sftp_errors[] = $error;
        }
    }

    /**
     * Canonicalize the Server-Side Path Name
     *
     * SFTP doesn't provide a mechanism by which the current working directory can be changed, so we'll emulate it.  Returns
     * the absolute (canonicalized) path.
     *
     * If canonicalize_paths has been disabled using disablePathCanonicalization(), $path is returned as-is.
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     * @see self::chdir()
     * @see self::disablePathCanonicalization()
     */
    public function realpath(string $path)
    {
        if ($this->precheck() === false) {
            return false;
        }

        if (!$this->canonicalize_paths) {
            if ($this->pwd === true) {
                return '.';
            }
            if (!strlen($path) || $path[0] != '/') {
                $path = $this->pwd . '/' . $path;
            }
            $parts = explode('/', $path);
            $afterPWD = $beforePWD = [];
            foreach ($parts as $part) {
                switch ($part) {
                    //case '': // some SFTP servers /require/ double /'s. see https://github.com/phpseclib/phpseclib/pull/1137
                    case '.':
                        break;
                    case '..':
                        if (!empty($afterPWD)) {
                            array_pop($afterPWD);
                        } else {
                            $beforePWD[] = '..';
                        }
                        break;
                    default:
                        $afterPWD[] = $part;
                }
            }
            $beforePWD = count($beforePWD) ? implode('/', $beforePWD) : '.';
            return $beforePWD . '/' . implode('/', $afterPWD);
        }

        if ($this->pwd === true) {
            // http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-8.9
            $this->send_sftp_packet(SFTPPacketType::REALPATH, Strings::packSSH2('s', $path));

            $response = $this->get_sftp_packet();
            switch ($this->packet_type) {
                case SFTPPacketType::NAME:
                    // although SSH_FXP_NAME is implemented differently in SFTPv3 than it is in SFTPv4+, the following
                    // should work on all SFTP versions since the only part of the SSH_FXP_NAME packet the following looks
                    // at is the first part and that part is defined the same in SFTP versions 3 through 6.
                    [, $filename] = Strings::unpackSSH2('Ns', $response);
                    return $filename;
                case SFTPPacketType::STATUS:
                    $this->logError($response);
                    return false;
                default:
                    throw new UnexpectedValueException('Expected PacketType::NAME or PacketType::STATUS. '
                                                      . 'Got packet type: ' . $this->packet_type);
            }
        }

        if (!strlen($path) || $path[0] != '/') {
            $path = $this->pwd . '/' . $path;
        }

        $path = explode('/', $path);
        $new = [];
        foreach ($path as $dir) {
            if (!strlen($dir)) {
                continue;
            }
            switch ($dir) {
                case '..':
                    array_pop($new);
                    // fall-through
                case '.':
                    break;
                default:
                    $new[] = $dir;
            }
        }

        return '/' . implode('/', $new);
    }

    /**
     * Changes the current directory
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    public function chdir(string $dir): bool
    {
        if (!$this->precheck()) {
            return false;
        }

        // assume current dir if $dir is empty
        if ($dir === '') {
            $dir = './';
        // suffix a slash if needed
        } elseif ($dir[-1] != '/') {
            $dir .= '/';
        }

        $dir = $this->realpath($dir);

        // confirm that $dir is, in fact, a valid directory
        if ($this->use_stat_cache && is_array($this->query_stat_cache($dir))) {
            $this->pwd = $dir;
            return true;
        }

        // we could do a stat on the alleged $dir to see if it's a directory but that doesn't tell us
        // the currently logged in user has the appropriate permissions or not. maybe you could see if
        // the file's uid / gid match the currently logged in user's uid / gid but how there's no easy
        // way to get those with SFTP

        $this->send_sftp_packet(SFTPPacketType::OPENDIR, Strings::packSSH2('s', $dir));

        // see \phpseclib3\Net\SFTP::nlist() for a more thorough explanation of the following
        $response = $this->get_sftp_packet();
        switch ($this->packet_type) {
            case SFTPPacketType::HANDLE:
                $handle = substr($response, 4);
                break;
            case SFTPPacketType::STATUS:
                $this->logError($response);
                return false;
            default:
                throw new UnexpectedValueException('Expected PacketType::HANDLE or PacketType::STATUS' .
                                                    'Got packet type: ' . $this->packet_type);
        }

        if (!$this->close_handle($handle)) {
            return false;
        }

        $this->update_stat_cache($dir, []);

        $this->pwd = $dir;
        return true;
    }

    /**
     * Returns a list of files in the given directory
     *
     * @return array|false
     */
    public function nlist(string $dir = '.', bool $recursive = false)
    {
        return $this->nlist_helper($dir, $recursive, '');
    }

    /**
     * Helper method for nlist
     *
     * @return array|false
     */
    private function nlist_helper(string $dir, bool $recursive, string $relativeDir)
    {
        $files = $this->readlist($dir, false);

        // If we get an int back, then that is an "unexpected" status.
        // We do not have a file list, so return false.
        if (is_int($files)) {
            return false;
        }

        if (!$recursive || $files === false) {
            return $files;
        }

        $result = [];
        foreach ($files as $value) {
            if ($value == '.' || $value == '..') {
                $result[] = $relativeDir . $value;
                continue;
            }
            if (is_array($this->query_stat_cache($this->realpath($dir . '/' . $value)))) {
                $temp = $this->nlist_helper($dir . '/' . $value, true, $relativeDir . $value . '/');
                $temp = is_array($temp) ? $temp : [];
                $result = array_merge($result, $temp);
            } else {
                $result[] = $relativeDir . $value;
            }
        }

        return $result;
    }

    /**
     * Returns a detailed list of files in the given directory
     *
     * @return array|false
     */
    public function rawlist(string $dir = '.', bool $recursive = false)
    {
        $files = $this->readlist($dir, true);

        // If we get an int back, then that is an "unexpected" status.
        // We do not have a file list, so return false.
        if (is_int($files)) {
            return false;
        }

        if (!$recursive || $files === false) {
            return $files;
        }

        static $depth = 0;

        foreach ($files as $key => $value) {
            if ($depth != 0 && $key == '..') {
                unset($files[$key]);
                continue;
            }
            $is_directory = false;
            if ($key != '.' && $key != '..') {
                if ($this->use_stat_cache) {
                    $is_directory = is_array($this->query_stat_cache($this->realpath($dir . '/' . $key)));
                } else {
                    $stat = $this->lstat($dir . '/' . $key);
                    $is_directory = $stat && $stat['type'] === FileType::DIRECTORY;
                }
            }

            if ($is_directory) {
                $depth++;
                $files[$key] = $this->rawlist($dir . '/' . $key, true);
                $depth--;
            } else {
                $files[$key] = (object) $value;
            }
        }

        return $files;
    }

    /**
     * Reads a list, be it detailed or not, of files in the given directory
     *
     * @return array|int|false array of files, integer status (if known) or false if something else is wrong
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    private function readlist(string $dir, bool $raw = true): array|int|false
    {
        if (!$this->precheck()) {
            return false;
        }

        $dir = $this->realpath($dir . '/');
        if ($dir === false) {
            return false;
        }

        // http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-8.1.2
        $this->send_sftp_packet(SFTPPacketType::OPENDIR, Strings::packSSH2('s', $dir));

        $response = $this->get_sftp_packet();
        switch ($this->packet_type) {
            case SFTPPacketType::HANDLE:
                // http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-9.2
                // since 'handle' is the last field in the SSH_FXP_HANDLE packet, we'll just remove the first four bytes that
                // represent the length of the string and leave it at that
                $handle = substr($response, 4);
                break;
            case SFTPPacketType::STATUS:
                // presumably SSH_FX_NO_SUCH_FILE or SSH_FX_PERMISSION_DENIED
                [$status] = Strings::unpackSSH2('N', $response);
                $this->logError($response, $status);
                return $status;
            default:
                throw new UnexpectedValueException('Expected PacketType::HANDLE or PacketType::STATUS. '
                                                  . 'Got packet type: ' . $this->packet_type);
        }

        $this->update_stat_cache($dir, []);

        $contents = [];
        while (true) {
            // http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-8.2.2
            // why multiple SSH_FXP_READDIR packets would be sent when the response to a single one can span arbitrarily many
            // SSH_MSG_CHANNEL_DATA messages is not known to me.
            $this->send_sftp_packet(SFTPPacketType::READDIR, Strings::packSSH2('s', $handle));

            $response = $this->get_sftp_packet();
            switch ($this->packet_type) {
                case SFTPPacketType::NAME:
                    [$count] = Strings::unpackSSH2('N', $response);
                    for ($i = 0; $i < $count; $i++) {
                        [$shortname] = Strings::unpackSSH2('s', $response);
                        // SFTPv4 "removed the long filename from the names structure-- it can now be
                        //         built from information available in the attrs structure."
                        if ($this->version < 4) {
                            [$longname] = Strings::unpackSSH2('s', $response);
                        }
                        $attributes = $this->parseAttributes($response);
                        if (!isset($attributes['type']) && $this->version < 4) {
                            $fileType = $this->parseLongname($longname);
                            if ($fileType) {
                                $attributes['type'] = $fileType;
                            }
                        }
                        $contents[$shortname] = $attributes + ['filename' => $shortname];

                        if (isset($attributes['type']) && $attributes['type'] == FileType::DIRECTORY && ($shortname != '.' && $shortname != '..')) {
                            $this->update_stat_cache($dir . '/' . $shortname, []);
                        } else {
                            if ($shortname == '..') {
                                $temp = $this->realpath($dir . '/..') . '/.';
                            } else {
                                $temp = $dir . '/' . $shortname;
                            }
                            $this->update_stat_cache($temp, (object) ['lstat' => $attributes]);
                        }
                        // SFTPv6 has an optional boolean end-of-list field, but we'll ignore that, since the
                        // final SSH_FXP_STATUS packet should tell us that, already.
                    }
                    break;
                case SFTPPacketType::STATUS:
                    [$status] = Strings::unpackSSH2('N', $response);
                    if ($status != StatusCode::EOF) {
                        $this->logError($response, $status);
                        return $status;
                    }
                    break 2;
                default:
                    throw new UnexpectedValueException('Expected PacketType::NAME or PacketType::STATUS. '
                                                      . 'Got packet type: ' . $this->packet_type);
            }
        }

        if (!$this->close_handle($handle)) {
            return false;
        }

        if (count($this->sortOptions)) {
            uasort($contents, [&$this, 'comparator']);
        }

        return $raw ? $contents : array_map('strval', array_keys($contents));
    }

    /**
     * Compares two rawlist entries using parameters set by setListOrder()
     *
     * Intended for use with uasort()
     */
    private function comparator(array $a, array $b): ?int
    {
        switch (true) {
            case $a['filename'] === '.' || $b['filename'] === '.':
                if ($a['filename'] === $b['filename']) {
                    return 0;
                }
                return $a['filename'] === '.' ? -1 : 1;
            case $a['filename'] === '..' || $b['filename'] === '..':
                if ($a['filename'] === $b['filename']) {
                    return 0;
                }
                return $a['filename'] === '..' ? -1 : 1;
            case isset($a['type']) && $a['type'] === FileType::DIRECTORY:
                if (!isset($b['type'])) {
                    return 1;
                }
                if ($b['type'] !== $a['type']) {
                    return -1;
                }
                break;
            case isset($b['type']) && $b['type'] === FileType::DIRECTORY:
                return 1;
        }
        foreach ($this->sortOptions as $sort => $order) {
            if (!isset($a[$sort]) || !isset($b[$sort])) {
                if (isset($a[$sort])) {
                    return -1;
                }
                if (isset($b[$sort])) {
                    return 1;
                }
                return 0;
            }
            switch ($sort) {
                case 'filename':
                    $result = strcasecmp($a['filename'], $b['filename']);
                    if ($result) {
                        return $order === SORT_DESC ? -$result : $result;
                    }
                    break;
                case 'mode':
                    $a[$sort] &= 0o7777;
                    $b[$sort] &= 0o7777;
                    // fall-through
                default:
                    if ($a[$sort] === $b[$sort]) {
                        break;
                    }
                    return $order === SORT_ASC ? $a[$sort] - $b[$sort] : $b[$sort] - $a[$sort];
            }
        }
        return null;
    }

    /**
     * Defines how nlist() and rawlist() will be sorted - if at all.
     *
     * If sorting is enabled directories and files will be sorted independently with
     * directories appearing before files in the resultant array that is returned.
     *
     * Any parameter returned by stat is a valid sort parameter for this function.
     * Filename comparisons are case insensitive.
     *
     * Examples:
     *
     * $sftp->setListOrder('filename', SORT_ASC);
     * $sftp->setListOrder('size', SORT_DESC, 'filename', SORT_ASC);
     * $sftp->setListOrder(true);
     *    Separates directories from files but doesn't do any sorting beyond that
     * $sftp->setListOrder();
     *    Don't do any sort of sorting
     *
     * @param string ...$args
     */
    public function setListOrder(...$args): void
    {
        $this->sortOptions = [];
        if (empty($args)) {
            return;
        }
        $len = count($args) & 0x7FFFFFFE;
        for ($i = 0; $i < $len; $i += 2) {
            $this->sortOptions[$args[$i]] = $args[$i + 1];
        }
        if (!count($this->sortOptions)) {
            $this->sortOptions = ['bogus' => true];
        }
    }

    /**
     * Save files / directories to cache
     */
    private function update_stat_cache(string $path, $value): void
    {
        if ($this->use_stat_cache === false) {
            return;
        }

        // preg_replace('#^/|/(?=/)|/$#', '', $dir) == str_replace('//', '/', trim($path, '/'))
        $dirs = explode('/', preg_replace('#^/|/(?=/)|/$#', '', $path));

        $temp = &$this->stat_cache;
        $max = count($dirs) - 1;
        foreach ($dirs as $i => $dir) {
            // if $temp is an object that means one of two things.
            //  1. a file was deleted and changed to a directory behind phpseclib's back
            //  2. it's a symlink. when lstat is done it's unclear what it's a symlink to
            if (is_object($temp)) {
                $temp = [];
            }
            if (!isset($temp[$dir])) {
                $temp[$dir] = [];
            }
            if ($i === $max) {
                if (is_object($temp[$dir]) && is_object($value)) {
                    if (!isset($value->stat) && isset($temp[$dir]->stat)) {
                        $value->stat = $temp[$dir]->stat;
                    }
                    if (!isset($value->lstat) && isset($temp[$dir]->lstat)) {
                        $value->lstat = $temp[$dir]->lstat;
                    }
                }
                $temp[$dir] = $value;
                break;
            }
            $temp = &$temp[$dir];
        }
    }

    /**
     * Remove files / directories from cache
     */
    private function remove_from_stat_cache(string $path): bool
    {
        $dirs = explode('/', preg_replace('#^/|/(?=/)|/$#', '', $path));

        $temp = &$this->stat_cache;
        $max = count($dirs) - 1;
        foreach ($dirs as $i => $dir) {
            if (!is_array($temp)) {
                return false;
            }
            if ($i === $max) {
                unset($temp[$dir]);
                return true;
            }
            if (!isset($temp[$dir])) {
                return false;
            }
            $temp = &$temp[$dir];
        }
    }

    /**
     * Checks cache for path
     *
     * Mainly used by file_exists
     */
    private function query_stat_cache(string $path)
    {
        $dirs = explode('/', preg_replace('#^/|/(?=/)|/$#', '', $path));

        $temp = &$this->stat_cache;
        foreach ($dirs as $dir) {
            if (!is_array($temp)) {
                return null;
            }
            if (!isset($temp[$dir])) {
                return null;
            }
            $temp = &$temp[$dir];
        }
        return $temp;
    }

    /**
     * Returns general information about a file.
     *
     * Returns an array on success and false otherwise.
     *
     * @return array|false
     */
    public function stat(string $filename)
    {
        if (!$this->precheck()) {
            return false;
        }

        $filename = $this->realpath($filename);
        if ($filename === false) {
            return false;
        }

        if ($this->use_stat_cache) {
            $result = $this->query_stat_cache($filename);
            if (is_array($result) && isset($result['.']) && isset($result['.']->stat)) {
                return $result['.']->stat;
            }
            if (is_object($result) && isset($result->stat)) {
                return $result->stat;
            }
        }

        $stat = $this->stat_helper($filename, SFTPPacketType::STAT);
        if ($stat === false) {
            $this->remove_from_stat_cache($filename);
            return false;
        }
        if (isset($stat['type'])) {
            if ($stat['type'] == FileType::DIRECTORY) {
                $filename .= '/.';
            }
            $this->update_stat_cache($filename, (object) ['stat' => $stat]);
            return $stat;
        }

        $pwd = $this->pwd;
        $stat['type'] = $this->chdir($filename) ?
            FileType::DIRECTORY :
            FileType::REGULAR;
        $this->pwd = $pwd;

        if ($stat['type'] == FileType::DIRECTORY) {
            $filename .= '/.';
        }
        $this->update_stat_cache($filename, (object) ['stat' => $stat]);

        return $stat;
    }

    /**
     * Returns general information about a file or symbolic link.
     *
     * Returns an array on success and false otherwise.
     *
     * @return array|false
     */
    public function lstat(string $filename)
    {
        if (!$this->precheck()) {
            return false;
        }

        $filename = $this->realpath($filename);
        if ($filename === false) {
            return false;
        }

        if ($this->use_stat_cache) {
            $result = $this->query_stat_cache($filename);
            if (is_array($result) && isset($result['.']) && isset($result['.']->lstat)) {
                return $result['.']->lstat;
            }
            if (is_object($result) && isset($result->lstat)) {
                return $result->lstat;
            }
        }

        $lstat = $this->stat_helper($filename, SFTPPacketType::LSTAT);
        if ($lstat === false) {
            $this->remove_from_stat_cache($filename);
            return false;
        }
        if (isset($lstat['type'])) {
            if ($lstat['type'] == FileType::DIRECTORY) {
                $filename .= '/.';
            }
            $this->update_stat_cache($filename, (object) ['lstat' => $lstat]);
            return $lstat;
        }

        $stat = $this->stat_helper($filename, SFTPPacketType::STAT);

        if ($lstat != $stat) {
            $lstat = array_merge($lstat, ['type' => FileType::SYMLINK]);
            $this->update_stat_cache($filename, (object) ['lstat' => $lstat]);
            return $stat;
        }

        $pwd = $this->pwd;
        $lstat['type'] = $this->chdir($filename) ?
            FileType::DIRECTORY :
            FileType::REGULAR;
        $this->pwd = $pwd;

        if ($lstat['type'] == FileType::DIRECTORY) {
            $filename .= '/.';
        }
        $this->update_stat_cache($filename, (object) ['lstat' => $lstat]);

        return $lstat;
    }

    /**
     * Returns general information about a file or symbolic link
     *
     * Determines information without calling \phpseclib3\Net\SFTP::realpath().
     * The second parameter can be either PacketType::STAT or PacketType::LSTAT.
     *
     * @return array|false
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    private function stat_helper(string $filename, int $type)
    {
        // SFTPv4+ adds an additional 32-bit integer field - flags - to the following:
        $packet = Strings::packSSH2('s', $filename);
        $this->send_sftp_packet($type, $packet);

        $response = $this->get_sftp_packet();
        switch ($this->packet_type) {
            case SFTPPacketType::ATTRS:
                return $this->parseAttributes($response);
            case SFTPPacketType::STATUS:
                $this->logError($response);
                return false;
        }

        throw new UnexpectedValueException('Expected PacketType::ATTRS or PacketType::STATUS. '
                                          . 'Got packet type: ' . $this->packet_type);
    }

    /**
     * Truncates a file to a given length
     */
    public function truncate(string $filename, int $new_size): bool
    {
        $attr = Strings::packSSH2('NQ', Attribute::SIZE, $new_size);

        return $this->setstat($filename, $attr, false);
    }

    /**
     * Sets access and modification time of file.
     *
     * If the file does not exist, it will be created.
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    public function touch(string $filename, ?int $time = null, ?int $atime = null): bool
    {
        if (!$this->precheck()) {
            return false;
        }

        $filename = $this->realpath($filename);
        if ($filename === false) {
            return false;
        }

        if (!isset($time)) {
            $time = time();
        }
        if (!isset($atime)) {
            $atime = $time;
        }

        $attr = $this->version < 4 ?
            pack('N3', Attribute::ACCESSTIME, $atime, $time) :
            Strings::packSSH2('NQ2', Attribute::ACCESSTIME | Attribute::MODIFYTIME, $atime, $time);

        $packet = Strings::packSSH2('s', $filename);
        $packet .= $this->version >= 5 ?
            pack('N2', 0, OpenFlag5::OPEN_EXISTING) :
            pack('N', OpenFlag::WRITE | OpenFlag::CREATE | OpenFlag::EXCL);
        $packet .= $attr;

        $this->send_sftp_packet(SFTPPacketType::OPEN, $packet);

        $response = $this->get_sftp_packet();
        switch ($this->packet_type) {
            case SFTPPacketType::HANDLE:
                return $this->close_handle(substr($response, 4));
            case SFTPPacketType::STATUS:
                $this->logError($response);
                break;
            default:
                throw new UnexpectedValueException('Expected PacketType::HANDLE or PacketType::STATUS. '
                                                  . 'Got packet type: ' . $this->packet_type);
        }

        return $this->setstat($filename, $attr, false);
    }

    /**
     * Changes file or directory owner
     *
     * $uid should be an int for SFTPv3 and a string for SFTPv4+. Ideally the string
     * would be of the form "user@dns_domain" but it does not need to be.
     * `$sftp->getSupportedVersions()['version']` will return the specific version
     * that's being used.
     *
     * Returns true on success or false on error.
     *
     * @param int|string $uid
     */
    public function chown(string $filename, $uid, bool $recursive = false): bool
    {
        /*
         quoting <https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13#section-7.5>,

         "To avoid a representation that is tied to a particular underlying
          implementation at the client or server, the use of UTF-8 strings has
          been chosen.  The string should be of the form "user@dns_domain".
          This will allow for a client and server that do not use the same
          local representation the ability to translate to a common syntax that
          can be interpreted by both.  In the case where there is no
          translation available to the client or server, the attribute value
          must be constructed without the "@"."

         phpseclib _could_ auto append the dns_domain to $uid BUT what if it shouldn't
         have one? phpseclib would have no way of knowing so rather than guess phpseclib
         will just use whatever value the user provided
       */

        $attr = $this->version < 4 ?
            // quoting <http://www.kernel.org/doc/man-pages/online/pages/man2/chown.2.html>,
            // "if the owner or group is specified as -1, then that ID is not changed"
            pack('N3', Attribute::UIDGID, $uid, -1) :
            // quoting <https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13#section-7.5>,
            // "If either the owner or group field is zero length, the field should be
            //  considered absent, and no change should be made to that specific field
            //  during a modification operation"
            Strings::packSSH2('Nss', Attribute::OWNERGROUP, $uid, '');

        return $this->setstat($filename, $attr, $recursive);
    }

    /**
     * Changes file or directory group
     *
     * $gid should be an int for SFTPv3 and a string for SFTPv4+. Ideally the string
     * would be of the form "user@dns_domain" but it does not need to be.
     * `$sftp->getSupportedVersions()['version']` will return the specific version
     * that's being used.
     *
     * Returns true on success or false on error.
     *
     * @param int|string $gid
     */
    public function chgrp(string $filename, $gid, bool $recursive = false): bool
    {
        $attr = $this->version < 4 ?
            pack('N3', Attribute::UIDGID, -1, $gid) :
            Strings::packSSH2('Nss', Attribute::OWNERGROUP, '', $gid);

        return $this->setstat($filename, $attr, $recursive);
    }

    /**
     * Set permissions on a file.
     *
     * Returns the new file permissions on success or false on error.
     * If $recursive is true than this just returns true or false.
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    public function chmod(int $mode, string $filename, bool $recursive = false)
    {
        if (is_string($mode) && is_int($filename)) {
            $temp = $mode;
            $mode = $filename;
            $filename = $temp;
        }

        $attr = pack('N2', Attribute::PERMISSIONS, $mode & 0o7777);
        if (!$this->setstat($filename, $attr, $recursive)) {
            return false;
        }
        if ($recursive) {
            return true;
        }

        $filename = $this->realpath($filename);
        // rather than return what the permissions *should* be, we'll return what they actually are.  this will also
        // tell us if the file actually exists.
        // incidentally, SFTPv4+ adds an additional 32-bit integer field - flags - to the following:
        $packet = pack('Na*', strlen($filename), $filename);
        $this->send_sftp_packet(SFTPPacketType::STAT, $packet);

        $response = $this->get_sftp_packet();
        switch ($this->packet_type) {
            case SFTPPacketType::ATTRS:
                $attrs = $this->parseAttributes($response);
                return $attrs['mode'];
            case SFTPPacketType::STATUS:
                $this->logError($response);
                return false;
        }

        throw new UnexpectedValueException('Expected PacketType::ATTRS or PacketType::STATUS. '
                                          . 'Got packet type: ' . $this->packet_type);
    }

    /**
     * Sets information about a file
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    private function setstat(string $filename, string $attr, bool $recursive): bool
    {
        if (!$this->precheck()) {
            return false;
        }

        $filename = $this->realpath($filename);
        if ($filename === false) {
            return false;
        }

        $this->remove_from_stat_cache($filename);

        if ($recursive) {
            $i = 0;
            $result = $this->setstat_recursive($filename, $attr, $i);
            $this->read_put_responses($i);
            return $result;
        }

        $packet = Strings::packSSH2('s', $filename);
        $packet .= $this->version >= 4 ?
            pack('a*Ca*', substr($attr, 0, 4), FileType::UNKNOWN, substr($attr, 4)) :
            $attr;
        $this->send_sftp_packet(SFTPPacketType::SETSTAT, $packet);

        /*
         "Because some systems must use separate system calls to set various attributes, it is possible that a failure
          response will be returned, but yet some of the attributes may be have been successfully modified.  If possible,
          servers SHOULD avoid this situation; however, clients MUST be aware that this is possible."

          -- http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-8.6
        */
        $response = $this->get_sftp_packet();
        if ($this->packet_type != SFTPPacketType::STATUS) {
            throw new UnexpectedValueException('Expected PacketType::STATUS. '
                                              . 'Got packet type: ' . $this->packet_type);
        }

        [$status] = Strings::unpackSSH2('N', $response);
        if ($status != StatusCode::OK) {
            $this->logError($response, $status);
            return false;
        }

        return true;
    }

    /**
     * Recursively sets information on directories on the SFTP server
     *
     * Minimizes directory lookups and SSH_FXP_STATUS requests for speed.
     */
    private function setstat_recursive(string $path, string $attr, int &$i): bool
    {
        if (!$this->read_put_responses($i)) {
            return false;
        }
        $i = 0;
        $entries = $this->readlist($path, true);

        if ($entries === false || is_int($entries)) {
            return $this->setstat($path, $attr, false);
        }

        // normally $entries would have at least . and .. but it might not if the directories
        // permissions didn't allow reading
        if (empty($entries)) {
            return false;
        }

        unset($entries['.'], $entries['..']);
        foreach ($entries as $filename => $props) {
            if (!isset($props['type'])) {
                return false;
            }

            $temp = $path . '/' . $filename;
            if ($props['type'] == FileType::DIRECTORY) {
                if (!$this->setstat_recursive($temp, $attr, $i)) {
                    return false;
                }
            } else {
                $packet = Strings::packSSH2('s', $temp);
                $packet .= $this->version >= 4 ?
                    pack('Ca*', FileType::UNKNOWN, $attr) :
                    $attr;
                $this->send_sftp_packet(SFTPPacketType::SETSTAT, $packet);

                $i++;

                if ($i >= $this->queueSize) {
                    if (!$this->read_put_responses($i)) {
                        return false;
                    }
                    $i = 0;
                }
            }
        }

        $packet = Strings::packSSH2('s', $path);
        $packet .= $this->version >= 4 ?
            pack('Ca*', FileType::UNKNOWN, $attr) :
            $attr;
        $this->send_sftp_packet(SFTPPacketType::SETSTAT, $packet);

        $i++;

        if ($i >= $this->queueSize) {
            if (!$this->read_put_responses($i)) {
                return false;
            }
            $i = 0;
        }

        return true;
    }

    /**
     * Return the target of a symbolic link
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    public function readlink(string $link)
    {
        if (!$this->precheck()) {
            return false;
        }

        $link = $this->realpath($link);

        $this->send_sftp_packet(SFTPPacketType::READLINK, Strings::packSSH2('s', $link));

        $response = $this->get_sftp_packet();
        switch ($this->packet_type) {
            case SFTPPacketType::NAME:
                break;
            case SFTPPacketType::STATUS:
                $this->logError($response);
                return false;
            default:
                throw new UnexpectedValueException('Expected PacketType::NAME or PacketType::STATUS. '
                                                  . 'Got packet type: ' . $this->packet_type);
        }

        [$count] = Strings::unpackSSH2('N', $response);
        // the file isn't a symlink
        if (!$count) {
            return false;
        }

        [$filename] = Strings::unpackSSH2('s', $response);

        return $filename;
    }

    /**
     * Create a symlink
     *
     * symlink() creates a symbolic link to the existing target with the specified name link.
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    public function symlink(string $target, string $link): bool
    {
        if (!$this->precheck()) {
            return false;
        }

        //$target = $this->realpath($target);
        $link = $this->realpath($link);

        /* quoting https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-09#section-12.1 :

           Changed the SYMLINK packet to be LINK and give it the ability to
           create hard links.  Also change it's packet number because many
           implementation implemented SYMLINK with the arguments reversed.
           Hopefully the new argument names make it clear which way is which.
        */
        if ($this->version == 6) {
            $type = SFTPPacketType::LINK;
            $packet = Strings::packSSH2('ssC', $link, $target, 1);
        } else {
            $type = SFTPPacketType::SYMLINK;
            /* quoting http://bxr.su/OpenBSD/usr.bin/ssh/PROTOCOL#347 :

               3.1. sftp: Reversal of arguments to SSH_FXP_SYMLINK

               When OpenSSH's sftp-server was implemented, the order of the arguments
               to the SSH_FXP_SYMLINK method was inadvertently reversed. Unfortunately,
               the reversal was not noticed until the server was widely deployed. Since
               fixing this to follow the specification would cause incompatibility, the
               current order was retained. For correct operation, clients should send
               SSH_FXP_SYMLINK as follows:

                   uint32      id
                   string      targetpath
                   string      linkpath */
            $packet = substr($this->server_identifier, 0, 15) == 'SSH-2.0-OpenSSH' ?
                Strings::packSSH2('ss', $target, $link) :
                Strings::packSSH2('ss', $link, $target);
        }
        $this->send_sftp_packet($type, $packet);

        $response = $this->get_sftp_packet();
        if ($this->packet_type != SFTPPacketType::STATUS) {
            throw new UnexpectedValueException('Expected PacketType::STATUS. '
                                              . 'Got packet type: ' . $this->packet_type);
        }

        [$status] = Strings::unpackSSH2('N', $response);
        if ($status != StatusCode::OK) {
            $this->logError($response, $status);
            return false;
        }

        return true;
    }

    /**
     * Creates a directory.
     */
    public function mkdir(string $dir, int $mode = -1, bool $recursive = false): bool
    {
        if (!$this->precheck()) {
            return false;
        }

        $dir = $this->realpath($dir);

        if ($recursive) {
            $dirs = explode('/', preg_replace('#/(?=/)|/$#', '', $dir));
            if (empty($dirs[0])) {
                array_shift($dirs);
                $dirs[0] = '/' . $dirs[0];
            }
            for ($i = 0; $i < count($dirs); $i++) {
                $temp = array_slice($dirs, 0, $i + 1);
                $temp = implode('/', $temp);
                $result = $this->mkdir_helper($temp, $mode);
            }
            return $result;
        }

        return $this->mkdir_helper($dir, $mode);
    }

    /**
     * Helper function for directory creation
     */
    private function mkdir_helper(string $dir, int $mode): bool
    {
        // send SSH_FXP_MKDIR without any attributes (that's what the \0\0\0\0 is doing)
        $this->send_sftp_packet(SFTPPacketType::MKDIR, Strings::packSSH2('s', $dir) . "\0\0\0\0");

        $response = $this->get_sftp_packet();
        if ($this->packet_type != SFTPPacketType::STATUS) {
            throw new UnexpectedValueException('Expected PacketType::STATUS. '
                                              . 'Got packet type: ' . $this->packet_type);
        }

        [$status] = Strings::unpackSSH2('N', $response);
        if ($status != StatusCode::OK) {
            $this->logError($response, $status);
            return false;
        }

        if ($mode !== -1) {
            $this->chmod($mode, $dir);
        }

        return true;
    }

    /**
     * Removes a directory.
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    public function rmdir(string $dir): bool
    {
        if (!$this->precheck()) {
            return false;
        }

        $dir = $this->realpath($dir);
        if ($dir === false) {
            return false;
        }

        $this->send_sftp_packet(SFTPPacketType::RMDIR, Strings::packSSH2('s', $dir));

        $response = $this->get_sftp_packet();
        if ($this->packet_type != SFTPPacketType::STATUS) {
            throw new UnexpectedValueException('Expected PacketType::STATUS. '
                                              . 'Got packet type: ' . $this->packet_type);
        }

        [$status] = Strings::unpackSSH2('N', $response);
        if ($status != StatusCode::OK) {
            // presumably SSH_FX_NO_SUCH_FILE or SSH_FX_PERMISSION_DENIED?
            $this->logError($response, $status);
            return false;
        }

        $this->remove_from_stat_cache($dir);
        // the following will do a soft delete, which would be useful if you deleted a file
        // and then tried to do a stat on the deleted file. the above, in contrast, does
        // a hard delete
        //$this->update_stat_cache($dir, false);

        return true;
    }

    /**
     * Uploads a file to the SFTP server.
     *
     * By default, \phpseclib3\Net\SFTP::put() does not read from the local filesystem.  $data is dumped directly into $remote_file.
     * So, for example, if you set $data to 'filename.ext' and then do \phpseclib3\Net\SFTP::get(), you will get a file, twelve bytes
     * long, containing 'filename.ext' as its contents.
     *
     * Setting $mode to self::SOURCE_LOCAL_FILE will change the above behavior.  With self::SOURCE_LOCAL_FILE, $remote_file will
     * contain as many bytes as filename.ext does on your local filesystem.  If your filename.ext is 1MB then that is how
     * large $remote_file will be, as well.
     *
     * Setting $mode to self::SOURCE_CALLBACK will use $data as callback function, which gets only one parameter -- number
     * of bytes to return, and returns a string if there is some data or null if there is no more data
     *
     * If $data is a resource then it'll be used as a resource instead.
     *
     * Currently, only binary mode is supported.  As such, if the line endings need to be adjusted, you will need to take
     * care of that, yourself.
     *
     * $mode can take an additional two parameters - self::RESUME and self::RESUME_START. These are bitwise AND'd with
     * $mode. So if you want to resume upload of a 300mb file on the local file system you'd set $mode to the following:
     *
     * self::SOURCE_LOCAL_FILE | self::RESUME
     *
     * If you wanted to simply append the full contents of a local file to the full contents of a remote file you'd replace
     * self::RESUME with self::RESUME_START.
     *
     * If $mode & (self::RESUME | self::RESUME_START) then self::RESUME_START will be assumed.
     *
     * $start and $local_start give you more fine grained control over this process and take precident over self::RESUME
     * when they're non-negative. ie. $start could let you write at the end of a file (like self::RESUME) or in the middle
     * of one. $local_start could let you start your reading from the end of a file (like self::RESUME_START) or in the
     * middle of one.
     *
     * Setting $local_start to > 0 or $mode | self::RESUME_START doesn't do anything unless $mode | self::SOURCE_LOCAL_FILE.
     *
     * {@internal ASCII mode for SFTPv4/5/6 can be supported by adding a new function - \phpseclib3\Net\SFTP::setMode().}
     *
     * @param resource|array|string $data
     * @throws UnexpectedValueException on receipt of unexpected packets
     * @throws BadFunctionCallException if you're uploading via a callback and the callback function is invalid
     * @throws FileNotFoundException if you're uploading via a file and the file doesn't exist
     */
    public function put(string $remote_file, $data, int $mode = self::SOURCE_STRING, int $start = -1, int $local_start = -1, ?callable $progressCallback = null): bool
    {
        if (!$this->precheck()) {
            return false;
        }

        $remote_file = $this->realpath($remote_file);
        if ($remote_file === false) {
            return false;
        }

        $this->remove_from_stat_cache($remote_file);

        if ($this->version >= 5) {
            $flags = OpenFlag5::OPEN_OR_CREATE;
        } else {
            $flags = OpenFlag::WRITE | OpenFlag::CREATE;
            // according to the SFTP specs, OpenFlag::APPEND should "force all writes to append data at the end of the file."
            // in practice, it doesn't seem to do that.
            //$flags|= ($mode & self::RESUME) ? OpenFlag::APPEND : OpenFlag::TRUNCATE;
        }

        if ($start >= 0) {
            $offset = $start;
        } elseif ($mode & (self::RESUME | self::RESUME_START)) {
            // if OpenFlag::APPEND worked as it should _size() wouldn't need to be called
            $stat = $this->stat($remote_file);
            $offset = $stat !== false && $stat['size'] ? $stat['size'] : 0;
        } else {
            $offset = 0;
            if ($this->version >= 5) {
                $flags = OpenFlag5::CREATE_TRUNCATE;
            } else {
                $flags |= OpenFlag::TRUNCATE;
            }
        }

        $this->remove_from_stat_cache($remote_file);

        $packet = Strings::packSSH2('s', $remote_file);
        $packet .= $this->version >= 5 ?
            pack('N3', 0, $flags, 0) :
            pack('N2', $flags, 0);
        $this->send_sftp_packet(SFTPPacketType::OPEN, $packet);

        $response = $this->get_sftp_packet();
        switch ($this->packet_type) {
            case SFTPPacketType::HANDLE:
                $handle = substr($response, 4);
                break;
            case SFTPPacketType::STATUS:
                $this->logError($response);
                return false;
            default:
                throw new UnexpectedValueException('Expected PacketType::HANDLE or PacketType::STATUS. '
                                                  . 'Got packet type: ' . $this->packet_type);
        }

        // http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-8.2.3
        $dataCallback = false;
        switch (true) {
            case $mode & self::SOURCE_CALLBACK:
                if (!is_callable($data)) {
                    throw new BadFunctionCallException("\$data should be is_callable() if you specify SOURCE_CALLBACK flag");
                }
                $dataCallback = $data;
                // do nothing
                break;
            case is_resource($data):
                $mode = $mode & ~self::SOURCE_LOCAL_FILE;
                $info = stream_get_meta_data($data);
                if (isset($info['wrapper_type']) && $info['wrapper_type'] == 'PHP' && $info['stream_type'] == 'Input') {
                    $fp = fopen('php://memory', 'w+');
                    stream_copy_to_stream($data, $fp);
                    rewind($fp);
                } else {
                    $fp = $data;
                }
                break;
            case $mode & self::SOURCE_LOCAL_FILE:
                if (!is_file($data)) {
                    throw new FileNotFoundException("$data is not a valid file");
                }
                $fp = @fopen($data, 'rb');
                if (!$fp) {
                    return false;
                }
        }

        if (isset($fp)) {
            $stat = fstat($fp);
            $size = !empty($stat) ? $stat['size'] : 0;

            if ($local_start >= 0) {
                fseek($fp, $local_start);
                $size -= $local_start;
            } elseif ($mode & self::RESUME) {
                fseek($fp, $offset);
                $size -= $offset;
            }
        } elseif ($dataCallback) {
            $size = 0;
        } else {
            $size = strlen($data);
        }

        $sent = 0;
        $size = $size < 0 ? ($size & 0x7FFFFFFF) + 0x80000000 : $size;

        $sftp_packet_size = $this->max_sftp_packet;
        // make the SFTP packet be exactly the SFTP packet size by including the bytes in the PacketType::WRITE packets "header"
        $sftp_packet_size -= strlen($handle) + 25;
        $i = $j = 0;
        while ($dataCallback || ($size === 0 || $sent < $size)) {
            if ($dataCallback) {
                $temp = $dataCallback($sftp_packet_size);
                if (is_null($temp)) {
                    break;
                }
            } else {
                $temp = isset($fp) ? fread($fp, $sftp_packet_size) : substr($data, $sent, $sftp_packet_size);
                if ($temp === false || $temp === '') {
                    break;
                }
            }

            $subtemp = $offset + $sent;
            $packet = pack('Na*N3a*', strlen($handle), $handle, $subtemp / 4294967296, $subtemp, strlen($temp), $temp);
            try {
                $this->send_sftp_packet(SFTPPacketType::WRITE, $packet, $j);
            } catch (\Exception $e) {
                if ($mode & self::SOURCE_LOCAL_FILE) {
                    fclose($fp);
                }
                throw $e;
            }
            $sent += strlen($temp);
            if (is_callable($progressCallback)) {
                $progressCallback($sent);
            }

            $i++;
            $j++;
            if ($i == $this->uploadQueueSize) {
                if (!$this->read_put_responses($i)) {
                    $i = 0;
                    break;
                }
                $i = 0;
            }
        }

        $result = $this->close_handle($handle);

        if (!$this->read_put_responses($i)) {
            if ($mode & self::SOURCE_LOCAL_FILE) {
                fclose($fp);
            }
            $this->close_handle($handle);
            return false;
        }

        if ($mode & SFTP::SOURCE_LOCAL_FILE) {
            if (isset($fp) && is_resource($fp)) {
                fclose($fp);
            }

            if ($this->preserveTime) {
                $stat = stat($data);
                $attr = $this->version < 4 ?
                    pack('N3', Attribute::ACCESSTIME, $stat['atime'], $stat['mtime']) :
                    Strings::packSSH2('NQ2', Attribute::ACCESSTIME | Attribute::MODIFYTIME, $stat['atime'], $stat['mtime']);
                if (!$this->setstat($remote_file, $attr, false)) {
                    throw new RuntimeException('Error setting file time');
                }
            }
        }

        return $result;
    }

    /**
     * Reads multiple successive SSH_FXP_WRITE responses
     *
     * Sending an SSH_FXP_WRITE packet and immediately reading its response isn't as efficient as blindly sending out $i
     * SSH_FXP_WRITEs, in succession, and then reading $i responses.
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    private function read_put_responses(int $i): bool
    {
        while ($i--) {
            $response = $this->get_sftp_packet();
            if ($this->packet_type != SFTPPacketType::STATUS) {
                throw new UnexpectedValueException('Expected PacketType::STATUS. '
                                                  . 'Got packet type: ' . $this->packet_type);
            }

            [$status] = Strings::unpackSSH2('N', $response);
            if ($status != StatusCode::OK) {
                $this->logError($response, $status);
                break;
            }
        }

        return $i < 0;
    }

    /**
     * Close handle
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    private function close_handle(string $handle): bool
    {
        $this->send_sftp_packet(SFTPPacketType::CLOSE, pack('Na*', strlen($handle), $handle));

        // "The client MUST release all resources associated with the handle regardless of the status."
        //  -- http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-8.1.3
        $response = $this->get_sftp_packet();
        if ($this->packet_type != SFTPPacketType::STATUS) {
            throw new UnexpectedValueException('Expected PacketType::STATUS. '
                                              . 'Got packet type: ' . $this->packet_type);
        }

        [$status] = Strings::unpackSSH2('N', $response);
        if ($status != StatusCode::OK) {
            $this->logError($response, $status);
            return false;
        }

        return true;
    }

    /**
     * Downloads a file from the SFTP server.
     *
     * Returns a string containing the contents of $remote_file if $local_file is left undefined or a boolean false if
     * the operation was unsuccessful.  If $local_file is defined, returns true or false depending on the success of the
     * operation.
     *
     * $offset and $length can be used to download files in chunks.
     *
     * @param string|bool|resource|callable $local_file
     * @return string|bool
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    public function get(string $remote_file, $local_file = false, int $offset = 0, int $length = -1, ?callable $progressCallback = null)
    {
        if (!$this->precheck()) {
            return false;
        }

        $remote_file = $this->realpath($remote_file);
        if ($remote_file === false) {
            return false;
        }

        $packet = Strings::packSSH2('s', $remote_file);
        $packet .= $this->version >= 5 ?
            pack('N3', 0, OpenFlag5::OPEN_EXISTING, 0) :
            pack('N2', OpenFlag::READ, 0);
        $this->send_sftp_packet(SFTPPacketType::OPEN, $packet);

        $response = $this->get_sftp_packet();
        switch ($this->packet_type) {
            case SFTPPacketType::HANDLE:
                $handle = substr($response, 4);
                break;
            case SFTPPacketType::STATUS: // presumably SSH_FX_NO_SUCH_FILE or SSH_FX_PERMISSION_DENIED
                $this->logError($response);
                return false;
            default:
                throw new UnexpectedValueException('Expected PacketType::HANDLE or PacketType::STATUS. '
                                                  . 'Got packet type: ' . $this->packet_type);
        }

        if (is_resource($local_file)) {
            $fp = $local_file;
            $stat = fstat($fp);
            $res_offset = $stat['size'];
        } else {
            $res_offset = 0;
            if ($local_file !== false && !is_callable($local_file)) {
                $fp = fopen($local_file, 'wb');
                if (!$fp) {
                    return false;
                }
            } else {
                $content = '';
            }
        }

        $fclose_check = $local_file !== false && !is_callable($local_file) && !is_resource($local_file);

        $start = $offset;
        $read = 0;
        while (true) {
            $i = 0;

            while ($i < $this->queueSize && ($length < 0 || $read < $length)) {
                $tempoffset = $start + $read;

                $packet_size = $length > 0 ? min($this->max_sftp_packet, $length - $read) : $this->max_sftp_packet;

                $packet = Strings::packSSH2('sN3', $handle, $tempoffset / 4294967296, $tempoffset, $packet_size);
                try {
                    $this->send_sftp_packet(SFTPPacketType::READ, $packet, $i);
                } catch (\Exception $e) {
                    if ($fclose_check) {
                        fclose($fp);
                    }
                    throw $e;
                }
                $packet = null;
                $read += $packet_size;
                $i++;
            }

            if (!$i) {
                break;
            }

            $packets_sent = $i - 1;

            $clear_responses = false;
            while ($i > 0) {
                $i--;

                if ($clear_responses) {
                    $this->get_sftp_packet($packets_sent - $i);
                    continue;
                } else {
                    $response = $this->get_sftp_packet($packets_sent - $i);
                }

                switch ($this->packet_type) {
                    case SFTPPacketType::DATA:
                        $temp = substr($response, 4);
                        $offset += strlen($temp);
                        if ($local_file === false) {
                            $content .= $temp;
                        } elseif (is_callable($local_file)) {
                            $local_file($temp);
                        } else {
                            fwrite($fp, $temp);
                        }
                        if (is_callable($progressCallback)) {
                            call_user_func($progressCallback, $offset);
                        }
                        $temp = null;
                        break;
                    case SFTPPacketType::STATUS:
                        // could, in theory, return false if !strlen($content) but we'll hold off for the time being
                        $this->logError($response);
                        $clear_responses = true; // don't break out of the loop yet, so we can read the remaining responses
                        break;
                    default:
                        if ($fclose_check) {
                            fclose($fp);
                        }
                        if ($this->channel_close) {
                            $this->partial_init = false;
                            $this->init_sftp_connection();
                            return false;
                        } else {
                            throw new UnexpectedValueException('Expected PacketType::DATA or PacketType::STATUS. '
                                                              . 'Got packet type: ' . $this->packet_type);
                        }
                }
                $response = null;
            }

            if ($clear_responses) {
                break;
            }
        }

        if ($fclose_check) {
            fclose($fp);

            if ($this->preserveTime) {
                $stat = $this->stat($remote_file);
                touch($local_file, $stat['mtime'], $stat['atime']);
            }
        }

        if (!$this->close_handle($handle)) {
            return false;
        }

        // if $content isn't set that means a file was written to
        return $content ?? true;
    }

    /**
     * Deletes a file on the SFTP server.
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    public function delete(string $path, bool $recursive = true): bool
    {
        if (!$this->precheck()) {
            return false;
        }

        if (is_object($path)) {
            // It's an object. Cast it as string before we check anything else.
            $path = (string) $path;
        }

        if (!is_string($path) || $path == '') {
            return false;
        }

        $path = $this->realpath($path);
        if ($path === false) {
            return false;
        }

        // http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-8.3
        $this->send_sftp_packet(SFTPPacketType::REMOVE, pack('Na*', strlen($path), $path));

        $response = $this->get_sftp_packet();
        if ($this->packet_type != SFTPPacketType::STATUS) {
            throw new UnexpectedValueException('Expected PacketType::STATUS. '
                                              . 'Got packet type: ' . $this->packet_type);
        }

        // if $status isn't SSH_FX_OK it's probably SSH_FX_NO_SUCH_FILE or SSH_FX_PERMISSION_DENIED
        [$status] = Strings::unpackSSH2('N', $response);
        if ($status != StatusCode::OK) {
            $this->logError($response, $status);
            if (!$recursive) {
                return false;
            }

            $i = 0;
            $result = $this->delete_recursive($path, $i);
            $this->read_put_responses($i);
            return $result;
        }

        $this->remove_from_stat_cache($path);

        return true;
    }

    /**
     * Recursively deletes directories on the SFTP server
     *
     * Minimizes directory lookups and SSH_FXP_STATUS requests for speed.
     */
    private function delete_recursive(string $path, int &$i): bool
    {
        if (!$this->read_put_responses($i)) {
            return false;
        }
        $i = 0;
        $entries = $this->readlist($path, true);

        // The folder does not exist at all, so we cannot delete it.
        if ($entries === StatusCode::NO_SUCH_FILE) {
            return false;
        }

        // Normally $entries would have at least . and .. but it might not if the directories
        // permissions didn't allow reading. If this happens then default to an empty list of files.
        if ($entries === false || is_int($entries)) {
            $entries = [];
        }

        unset($entries['.'], $entries['..']);
        foreach ($entries as $filename => $props) {
            if (!isset($props['type'])) {
                return false;
            }

            $temp = $path . '/' . $filename;
            if ($props['type'] == FileType::DIRECTORY) {
                if (!$this->delete_recursive($temp, $i)) {
                    return false;
                }
            } else {
                $this->send_sftp_packet(SFTPPacketType::REMOVE, Strings::packSSH2('s', $temp));
                $this->remove_from_stat_cache($temp);

                $i++;

                if ($i >= $this->queueSize) {
                    if (!$this->read_put_responses($i)) {
                        return false;
                    }
                    $i = 0;
                }
            }
        }

        $this->send_sftp_packet(SFTPPacketType::RMDIR, Strings::packSSH2('s', $path));
        $this->remove_from_stat_cache($path);

        $i++;

        if ($i >= $this->queueSize) {
            if (!$this->read_put_responses($i)) {
                return false;
            }
            $i = 0;
        }

        return true;
    }

    /**
     * Checks whether a file or directory exists
     */
    public function file_exists(string $path): bool
    {
        if ($this->use_stat_cache) {
            if (!$this->precheck()) {
                return false;
            }

            $path = $this->realpath($path);

            $result = $this->query_stat_cache($path);

            if (isset($result)) {
                // return true if $result is an array or if it's an stdClass object
                return $result !== false;
            }
        }

        return $this->stat($path) !== false;
    }

    /**
     * Tells whether the filename is a directory
     */
    public function is_dir(string $path): bool
    {
        $result = $this->get_stat_cache_prop($path, 'type');
        if ($result === false) {
            return false;
        }
        return $result === FileType::DIRECTORY;
    }

    /**
     * Tells whether the filename is a regular file
     */
    public function is_file(string $path): bool
    {
        $result = $this->get_stat_cache_prop($path, 'type');
        if ($result === false) {
            return false;
        }
        return $result === FileType::REGULAR;
    }

    /**
     * Tells whether the filename is a symbolic link
     */
    public function is_link(string $path): bool
    {
        $result = $this->get_lstat_cache_prop($path, 'type');
        if ($result === false) {
            return false;
        }
        return $result === FileType::SYMLINK;
    }

    /**
     * Tells whether a file exists and is readable
     */
    public function is_readable(string $path): bool
    {
        if (!$this->precheck()) {
            return false;
        }

        $packet = Strings::packSSH2('sNN', $this->realpath($path), OpenFlag::READ, 0);
        $this->send_sftp_packet(SFTPPacketType::OPEN, $packet);

        $response = $this->get_sftp_packet();
        switch ($this->packet_type) {
            case SFTPPacketType::HANDLE:
                return true;
            case SFTPPacketType::STATUS: // presumably SSH_FX_NO_SUCH_FILE or SSH_FX_PERMISSION_DENIED
                return false;
            default:
                throw new UnexpectedValueException('Expected PacketType::HANDLE or PacketType::STATUS. '
                                                  . 'Got packet type: ' . $this->packet_type);
        }
    }

    /**
     * Tells whether the filename is writable
     */
    public function is_writable(string $path): bool
    {
        if (!$this->precheck()) {
            return false;
        }

        $packet = Strings::packSSH2('sNN', $this->realpath($path), OpenFlag::WRITE, 0);
        $this->send_sftp_packet(SFTPPacketType::OPEN, $packet);

        $response = $this->get_sftp_packet();
        switch ($this->packet_type) {
            case SFTPPacketType::HANDLE:
                return true;
            case SFTPPacketType::STATUS: // presumably SSH_FX_NO_SUCH_FILE or SSH_FX_PERMISSION_DENIED
                return false;
            default:
                throw new UnexpectedValueException('Expected SSH_FXP_HANDLE or SSH_FXP_STATUS. '
                                                  . 'Got packet type: ' . $this->packet_type);
        }
    }

    /**
     * Tells whether the filename is writeable
     *
     * Alias of is_writable
     */
    public function is_writeable(string $path): bool
    {
        return $this->is_writable($path);
    }

    /**
     * Gets last access time of file
     */
    public function fileatime(string $path)
    {
        return $this->get_stat_cache_prop($path, 'atime');
    }

    /**
     * Gets file modification time
     */
    public function filemtime(string $path)
    {
        return $this->get_stat_cache_prop($path, 'mtime');
    }

    /**
     * Gets file permissions
     */
    public function fileperms(string $path)
    {
        return $this->get_stat_cache_prop($path, 'mode');
    }

    /**
     * Gets file owner
     */
    public function fileowner(string $path)
    {
        return $this->get_stat_cache_prop($path, 'uid');
    }

    /**
     * Gets file group
     */
    public function filegroup(string $path)
    {
        return $this->get_stat_cache_prop($path, 'gid');
    }

    /**
     * Recursively go through rawlist() output to get the total filesize
     */
    private static function recursiveFilesize(array $files): int
    {
        $size = 0;
        foreach ($files as $name => $file) {
            if ($name == '.' || $name == '..') {
                continue;
            }
            $size += is_array($file) ?
                self::recursiveFilesize($file) :
                $file->size;
        }
        return $size;
    }

    /**
     * Gets file size
     */
    public function filesize(string $path, bool $recursive = false)
    {
        return !$recursive || $this->filetype($path) != 'dir' ?
            $this->get_stat_cache_prop($path, 'size') :
            self::recursiveFilesize($this->rawlist($path, true));
    }

    /**
     * Gets file type
     *
     * @return string|false
     */
    public function filetype(string $path)
    {
        $type = $this->get_stat_cache_prop($path, 'type');
        if ($type === false) {
            return false;
        }

        switch ($type) {
            case FileType::BLOCK_DEVICE:
                return 'block';
            case FileType::CHAR_DEVICE:
                return 'char';
            case FileType::DIRECTORY:
                return 'dir';
            case FileType::FIFO:
                return 'fifo';
            case FileType::REGULAR:
                return 'file';
            case FileType::SYMLINK:
                return 'link';
            default:
                return false;
        }
    }

    /**
     * Return a stat properity
     *
     * Uses cache if appropriate.
     */
    private function get_stat_cache_prop(string $path, string $prop)
    {
        return $this->get_xstat_cache_prop($path, $prop, 'stat');
    }

    /**
     * Return an lstat properity
     *
     * Uses cache if appropriate.
     */
    private function get_lstat_cache_prop(string $path, string $prop)
    {
        return $this->get_xstat_cache_prop($path, $prop, 'lstat');
    }

    /**
     * Return a stat or lstat properity
     *
     * Uses cache if appropriate.
     */
    private function get_xstat_cache_prop(string $path, string $prop, string $type)
    {
        if (!$this->precheck()) {
            return false;
        }

        if ($this->use_stat_cache) {
            $path = $this->realpath($path);

            $result = $this->query_stat_cache($path);

            if (is_object($result) && isset($result->$type)) {
                return $result->{$type}[$prop];
            }
        }

        $result = $this->$type($path);

        if ($result === false || !isset($result[$prop])) {
            return false;
        }

        return $result[$prop];
    }

    /**
     * Renames a file or a directory on the SFTP server.
     *
     * If the file already exists this will return false
     *
     * @throws UnexpectedValueException on receipt of unexpected packets
     */
    public function rename(string $oldname, string $newname): bool
    {
        if (!$this->precheck()) {
            return false;
        }

        $oldname = $this->realpath($oldname);
        $newname = $this->realpath($newname);
        if ($oldname === false || $newname === false) {
            return false;
        }

        // http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-8.3
        $packet = Strings::packSSH2('ss', $oldname, $newname);
        if ($this->version >= 5) {
            /* quoting https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-05#section-6.5 ,

               'flags' is 0 or a combination of:

                   SSH_FXP_RENAME_OVERWRITE  0x00000001
                   SSH_FXP_RENAME_ATOMIC     0x00000002
                   SSH_FXP_RENAME_NATIVE     0x00000004

               (none of these are currently supported) */
            $packet .= "\0\0\0\0";
        }
        $this->send_sftp_packet(SFTPPacketType::RENAME, $packet);

        $response = $this->get_sftp_packet();
        if ($this->packet_type != SFTPPacketType::STATUS) {
            throw new UnexpectedValueException('Expected PacketType::STATUS. '
                                              . 'Got packet type: ' . $this->packet_type);
        }

        // if $status isn't SSH_FX_OK it's probably SSH_FX_NO_SUCH_FILE or SSH_FX_PERMISSION_DENIED
        /**
         * @var int $status
         */
        [$status] = Strings::unpackSSH2('N', $response);
        if ($status != StatusCode::OK) {
            $this->logError($response, $status);
            return false;
        }

        // don't move the stat cache entry over since this operation could very well change the
        // atime and mtime attributes
        //$this->update_stat_cache($newname, $this->query_stat_cache($oldname));
        $this->remove_from_stat_cache($oldname);
        $this->remove_from_stat_cache($newname);

        return true;
    }

    /**
     * Parse Time
     *
     * See '7.7.  Times' of draft-ietf-secsh-filexfer-13 for more info.
     */
    private function parseTime(string $key, int $flags, string &$response): array
    {
        $attr = [];
        [$attr[$key]] = Strings::unpackSSH2('Q', $response);
        if ($flags & Attribute::SUBSECOND_TIMES) {
            [$attr[$key . '-nseconds']] = Strings::unpackSSH2('N', $response);
        }
        return $attr;
    }

    /**
     * Parse Attributes
     *
     * See '7.  File Attributes' of draft-ietf-secsh-filexfer-13 for more info.
     */
    protected function parseAttributes(string &$response): array
    {
        if ($this->version >= 4) {
            [$flags, $attr['type']] = Strings::unpackSSH2('NC', $response);
        } else {
            [$flags] = Strings::unpackSSH2('N', $response);
        }

        foreach (Attribute::getConstants() as $value => $key) {
            switch ($flags & $key) {
                case Attribute::UIDGID:
                    if ($this->version > 3) {
                        continue 2;
                    }
                    break;
                case Attribute::CREATETIME:
                case Attribute::MODIFYTIME:
                case Attribute::ACL:
                case Attribute::OWNERGROUP:
                case Attribute::SUBSECOND_TIMES:
                    if ($this->version < 4) {
                        continue 2;
                    }
                    break;
                case Attribute::BITS:
                    if ($this->version < 5) {
                        continue 2;
                    }
                    break;
                case Attribute::ALLOCATION_SIZE:
                case Attribute::TEXT_HINT:
                case Attribute::MIME_TYPE:
                case Attribute::LINK_COUNT:
                case Attribute::UNTRANSLATED_NAME:
                case Attribute::CTIME:
                    if ($this->version < 6) {
                        continue 2;
                    }
            }
            switch ($flags & $key) {
                case Attribute::SIZE:             // 0x00000001
                    // The size attribute is defined as an unsigned 64-bit integer.
                    // The following will use floats on 32-bit platforms, if necessary.
                    // As can be seen in the BigInteger class, floats are generally
                    // IEEE 754 binary64 "double precision" on such platforms and
                    // as such can represent integers of at least 2^50 without loss
                    // of precision. Interpreted in filesize, 2^50 bytes = 1024 TiB.
                    [$attr['size']] = Strings::unpackSSH2('Q', $response);
                    break;
                case Attribute::UIDGID: // 0x00000002 (SFTPv3 only)
                    [$attr['uid'], $attr['gid']] = Strings::unpackSSH2('NN', $response);
                    break;
                case Attribute::PERMISSIONS: // 0x00000004
                    [$attr['mode']] = Strings::unpackSSH2('N', $response);
                    $fileType = $this->parseMode($attr['mode']);
                    if ($this->version < 4 && $fileType !== false) {
                        $attr += ['type' => $fileType];
                    }
                    break;
                case Attribute::ACCESSTIME: // 0x00000008
                    if ($this->version >= 4) {
                        $attr += $this->parseTime('atime', $flags, $response);
                        break;
                    }
                    [$attr['atime'], $attr['mtime']] = Strings::unpackSSH2('NN', $response);
                    break;
                case Attribute::CREATETIME:       // 0x00000010 (SFTPv4+)
                    $attr += $this->parseTime('createtime', $flags, $response);
                    break;
                case Attribute::MODIFYTIME:       // 0x00000020
                    $attr += $this->parseTime('mtime', $flags, $response);
                    break;
                case Attribute::ACL:              // 0x00000040
                    // access control list
                    // see https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-04#section-5.7
                    // currently unsupported
                    [$count] = Strings::unpackSSH2('N', $response);
                    for ($i = 0; $i < $count; $i++) {
                        [$type, $flag, $mask, $who] = Strings::unpackSSH2('N3s', $result);
                    }
                    break;
                case Attribute::OWNERGROUP:       // 0x00000080
                    [$attr['owner'], $attr['$group']] = Strings::unpackSSH2('ss', $response);
                    break;
                case Attribute::SUBSECOND_TIMES:  // 0x00000100
                    break;
                case Attribute::BITS:             // 0x00000200 (SFTPv5+)
                    // see https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-05#section-5.8
                    // currently unsupported
                    // tells if you file is:
                    // readonly, system, hidden, case inensitive, archive, encrypted, compressed, sparse
                    // append only, immutable, sync
                    [$attrib_bits, $attrib_bits_valid] = Strings::unpackSSH2('N2', $response);
                    // if we were actually gonna implement the above it ought to be
                    // $attr['attrib-bits'] and $attr['attrib-bits-valid']
                    // eg. - instead of _
                    break;
                case Attribute::ALLOCATION_SIZE:  // 0x00000400 (SFTPv6+)
                    // see https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13#section-7.4
                    // represents the number of bytes that the file consumes on the disk. will
                    // usually be larger than the 'size' field
                    [$attr['allocation-size']] = Strings::unpackSSH2('Q', $response);
                    break;
                case Attribute::TEXT_HINT:        // 0x00000800
                    // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13#section-7.10
                    // currently unsupported
                    // tells if file is "known text", "guessed text", "known binary", "guessed binary"
                    [$text_hint] = Strings::unpackSSH2('C', $response);
                    // the above should be $attr['text-hint']
                    break;
                case Attribute::MIME_TYPE:        // 0x00001000
                    // see https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13#section-7.11
                    [$attr['mime-type']] = Strings::unpackSSH2('s', $response);
                    break;
                case Attribute::LINK_COUNT:       // 0x00002000
                    // see https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13#section-7.12
                    [$attr['link-count']] = Strings::unpackSSH2('N', $response);
                    break;
                case Attribute::UNTRANSLATED_NAME:// 0x00004000
                    // see https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13#section-7.13
                    [$attr['untranslated-name']] = Strings::unpackSSH2('s', $response);
                    break;
                case Attribute::CTIME:            // 0x00008000
                    // 'ctime' contains the last time the file attributes were changed.  The
                    // exact meaning of this field depends on the server.
                    $attr += $this->parseTime('ctime', $flags, $response);
                    break;
                case Attribute::EXTENDED: // 0x80000000
                    [$count] = Strings::unpackSSH2('N', $response);
                    for ($i = 0; $i < $count; $i++) {
                        [$key, $value] = Strings::unpackSSH2('ss', $response);
                        $attr[$key] = $value;
                    }
            }
        }
        return $attr;
    }

    /**
     * Attempt to identify the file type
     *
     * Quoting the SFTP RFC, "Implementations MUST NOT send bits that are not defined" but they seem to anyway
     *
     * @return int
     */
    private function parseMode(int $mode)
    {
        // values come from http://lxr.free-electrons.com/source/include/uapi/linux/stat.h#L12
        // see, also, http://linux.die.net/man/2/stat
        switch ($mode & 0o170000) {// ie. 1111 0000 0000 0000
            case 0: // no file type specified - figure out the file type using alternative means
                return false;
            case 0o040000:
                return FileType::DIRECTORY;
            case 0o100000:
                return FileType::REGULAR;
            case 0o120000:
                return FileType::SYMLINK;
            // new types introduced in SFTPv5+
            // http://tools.ietf.org/html/draft-ietf-secsh-filexfer-05#section-5.2
            case 0o010000: // named pipe (fifo)
                return FileType::FIFO;
            case 0o020000: // character special
                return FileType::CHAR_DEVICE;
            case 0o060000: // block special
                return FileType::BLOCK_DEVICE;
            case 0o140000: // socket
                return FileType::SOCKET;
            case 0o160000: // whiteout
                // "SPECIAL should be used for files that are of
                //  a known type which cannot be expressed in the protocol"
                return FileType::SPECIAL;
            default:
                return FileType::UNKNOWN;
        }
    }

    /**
     * Parse Longname
     *
     * SFTPv3 doesn't provide any easy way of identifying a file type.  You could try to open
     * a file as a directory and see if an error is returned or you could try to parse the
     * SFTPv3-specific longname field of the SSH_FXP_NAME packet.  That's what this function does.
     * The result is returned using the
     * {@link http://tools.ietf.org/html/draft-ietf-secsh-filexfer-04#section-5.2 SFTPv4 type constants}.
     *
     * If the longname is in an unrecognized format bool(false) is returned.
     */
    private function parseLongname(string $longname)
    {
        // http://en.wikipedia.org/wiki/Unix_file_types
        // http://en.wikipedia.org/wiki/Filesystem_permissions#Notation_of_traditional_Unix_permissions
        if (preg_match('#^[^/]([r-][w-][xstST-]){3}#', $longname)) {
            switch ($longname[0]) {
                case '-':
                    return FileType::REGULAR;
                case 'd':
                    return FileType::DIRECTORY;
                case 'l':
                    return FileType::SYMLINK;
                default:
                    return FileType::SPECIAL;
            }
        }

        return false;
    }

    /**
     * Sends SFTP Packets
     *
     * See '6. General Packet Format' of draft-ietf-secsh-filexfer-13 for more info.
     *
     * @see self::_get_sftp_packet()
     * @see self::send_channel_packet()
     */
    private function send_sftp_packet(int $type, string $data, int $request_id = 1): void
    {
        // in SSH2.php the timeout is cumulative per function call. eg. exec() will
        // timeout after 10s. but for SFTP.php it's cumulative per packet
        $this->curTimeout = $this->timeout;
        $this->is_timeout = false;

        $packet = $this->use_request_id ?
            pack('NCNa*', strlen($data) + 5, $type, $request_id, $data) :
            pack('NCa*', strlen($data) + 1, $type, $data);

        $start = microtime(true);
        $this->send_channel_packet(self::CHANNEL, $packet);
        $stop = microtime(true);

        if (defined('NET_SFTP_LOGGING')) {
            $packet_type = '-> ' . $this->packet_types[$type] .
                           ' (' . round($stop - $start, 4) . 's)';
            $this->append_log($packet_type, $data);
        }
    }

    /**
     * Resets the SFTP channel for re-use
     */
    private function reset_sftp(): void
    {
        $this->use_request_id = false;
        $this->pwd = false;
        $this->requestBuffer = [];
        $this->partial_init = false;
    }

    /**
     * Resets a connection for re-use
     */
    protected function reset_connection(): void
    {
        parent::reset_connection();
        $this->reset_sftp();
    }

    /**
     * Receives SFTP Packets
     *
     * See '6. General Packet Format' of draft-ietf-secsh-filexfer-13 for more info.
     *
     * Incidentally, the number of SSH_MSG_CHANNEL_DATA messages has no bearing on the number of SFTP packets present.
     * There can be one SSH_MSG_CHANNEL_DATA messages containing two SFTP packets or there can be two SSH_MSG_CHANNEL_DATA
     * messages containing one SFTP packet.
     *
     * @see self::_send_sftp_packet()
     * @return string
     */
    private function get_sftp_packet($request_id = null)
    {
        $this->channel_close = false;

        if (isset($request_id) && isset($this->requestBuffer[$request_id])) {
            $this->packet_type = $this->requestBuffer[$request_id]['packet_type'];
            $temp = $this->requestBuffer[$request_id]['packet'];
            unset($this->requestBuffer[$request_id]);
            return $temp;
        }

        // in SSH2.php the timeout is cumulative per function call. eg. exec() will
        // timeout after 10s. but for SFTP.php it's cumulative per packet
        $this->curTimeout = $this->timeout;
        $this->is_timeout = false;

        $start = microtime(true);

        // SFTP packet length
        while (strlen($this->packet_buffer) < 4) {
            $temp = $this->get_channel_packet(self::CHANNEL, true);
            if ($temp === true) {
                if ($this->channel_status[self::CHANNEL] === SSH2MessageType::CHANNEL_CLOSE) {
                    $this->channel_close = true;
                }
                $this->packet_type = false;
                $this->packet_buffer = '';
                return false;
            }
            $this->packet_buffer .= $temp;
        }
        if (strlen($this->packet_buffer) < 4) {
            throw new RuntimeException('Packet is too small');
        }
        extract(unpack('Nlength', Strings::shift($this->packet_buffer, 4)));
        /** @var integer $length */

        $tempLength = $length;
        $tempLength -= strlen($this->packet_buffer);

        // 256 * 1024 is what SFTP_MAX_MSG_LENGTH is set to in OpenSSH's sftp-common.h
        if (!$this->allow_arbitrary_length_packets && !$this->use_request_id && $tempLength > 256 * 1024) {
            throw new RuntimeException('Invalid Size');
        }

        // SFTP packet type and data payload
        while ($tempLength > 0) {
            $temp = $this->get_channel_packet(self::CHANNEL, true);
            if ($temp === true) {
                if ($this->channel_status[self::CHANNEL] === SSH2MessageType::CHANNEL_CLOSE) {
                    $this->channel_close = true;
                }
                $this->packet_type = false;
                $this->packet_buffer = '';
                return false;
            }
            $this->packet_buffer .= $temp;
            $tempLength -= strlen($temp);
        }

        $stop = microtime(true);

        $this->packet_type = ord(Strings::shift($this->packet_buffer));

        if ($this->use_request_id) {
            extract(unpack('Npacket_id', Strings::shift($this->packet_buffer, 4))); // remove the request id
            $length -= 5; // account for the request id and the packet type
        } else {
            $length -= 1; // account for the packet type
        }

        $packet = Strings::shift($this->packet_buffer, $length);

        if (defined('NET_SFTP_LOGGING')) {
            $packet_type = '<- ' . $this->packet_types[$this->packet_type] .
                           ' (' . round($stop - $start, 4) . 's)';
            $this->append_log($packet_type, $packet);
        }

        if (isset($request_id) && $this->use_request_id && $packet_id != $request_id) {
            $this->requestBuffer[$packet_id] = [
                'packet_type' => $this->packet_type,
                'packet' => $packet,
            ];
            return $this->get_sftp_packet($request_id);
        }

        return $packet;
    }

    /**
     * Logs data packets
     *
     * Makes sure that only the last 1MB worth of packets will be logged
     */
    private function append_log(string $message_number, string $message): void
    {
        $this->append_log_helper(
            NET_SFTP_LOGGING,
            $message_number,
            $message,
            $this->packet_type_log,
            $this->packet_log,
            $this->log_size,
            $this->realtime_log_file,
            $this->realtime_log_wrap,
            $this->realtime_log_size
        );
    }

    /**
     * Returns a log of the packets that have been sent and received.
     *
     * Returns a string if PacketType::LOGGING == self::LOG_COMPLEX, an array if PacketType::LOGGING == self::LOG_SIMPLE and false if !defined('NET_SFTP_LOGGING')
     *
     * @return array|string|false
     */
    public function getSFTPLog()
    {
        if (!defined('NET_SFTP_LOGGING')) {
            return false;
        }

        switch (NET_SFTP_LOGGING) {
            case self::LOG_COMPLEX:
                return $this->format_log($this->packet_log, $this->packet_type_log);
                break;
            //case self::LOG_SIMPLE:
            default:
                return $this->packet_type_log;
        }
    }

    /**
     * Returns all errors on the SFTP layer
     */
    public function getSFTPErrors(): array
    {
        return $this->sftp_errors;
    }

    /**
     * Returns the last error on the SFTP layer
     */
    public function getLastSFTPError(): string
    {
        return count($this->sftp_errors) ? $this->sftp_errors[count($this->sftp_errors) - 1] : '';
    }

    /**
     * Get supported SFTP versions
     *
     * @return array
     */
    public function getSupportedVersions()
    {
        if (!($this->bitmap & SSH2::MASK_LOGIN)) {
            return false;
        }

        if (!$this->partial_init) {
            $this->partial_init_sftp_connection();
        }

        $temp = ['version' => $this->defaultVersion];
        if (isset($this->extensions['versions'])) {
            $temp['extensions'] = $this->extensions['versions'];
        }
        return $temp;
    }

    /**
     * Get supported SFTP versions
     *
     * @return int|false
     */
    public function getNegotiatedVersion()
    {
        if (!$this->precheck()) {
            return false;
        }

        return $this->version;
    }

    /**
     * Set preferred version
     *
     * If you're preferred version isn't supported then the highest supported
     * version of SFTP will be utilized. Set to null or false or int(0) to
     * unset the preferred version
     */
    public function setPreferredVersion(int $version): void
    {
        $this->preferredVersion = $version;
    }

    /**
     * Disconnect
     *
     * @return false
     */
    protected function disconnect_helper(int $reason): bool
    {
        $this->pwd = false;
        return parent::disconnect_helper($reason);
    }

    /**
     * Enable Date Preservation
     */
    public function enableDatePreservation(): void
    {
        $this->preserveTime = true;
    }

    /**
     * Disable Date Preservation
     */
    public function disableDatePreservation(): void
    {
        $this->preserveTime = false;
    }

    public function posix_rename(string $oldname, string $newname): bool {
        if (!$this->precheck()) {
            return false;
        }
        if (!isset($this->extensions['posix-rename@openssh.com']) || $this->extensions['posix-rename@openssh.com'] !== '1') {
            throw new \RuntimeException("Extension 'posix-rename@openssh.com' is not supported by the server");
        }

        $oldname = $this->realpath($oldname);
        $newname = $this->realpath($newname);
        if ($oldname === false || $newname === false) {
            return false;
        }

        $packet = Strings::packSSH2('sss', 'posix-rename@openssh.com', $oldname, $newname);
        $this->send_sftp_packet(NET_SFTP_EXTENDED, $packet);

        $response = $this->get_sftp_packet();
        if ($this->packet_type != NET_SFTP_STATUS) {
            throw new \UnexpectedValueException('Expected NET_SFTP_STATUS. '
                . 'Got packet type: ' . $this->packet_type);
        }

        // if $status isn't SSH_FX_OK it's probably SSH_FX_NO_SUCH_FILE or SSH_FX_PERMISSION_DENIED
        list($status) = Strings::unpackSSH2('N', $response);
        if ($status != NET_SFTP_STATUS_OK) {
            $this->logError($response, $status);
            return false;
        }

        // don't move the stat cache entry over since this operation could very well change the
        // atime and mtime attributes
        //$this->update_stat_cache($newname, $this->query_stat_cache($oldname));
        $this->remove_from_stat_cache($oldname);
        $this->remove_from_stat_cache($newname);

        return true;
    }

    /**
     * @return array{bsize: int, frsize: int, blocks: int, bfree: int, bavail: int, files: int, ffree: int, favail: int, fsid: int, flag: int, namemax: int}
     */
    public function statvfs(string $path): array|bool {
        if (!isset($this->extensions['statvfs@openssh.com']) || $this->extensions['statvfs@openssh.com'] !== '1') {
            throw new \RuntimeException("Extension 'statvfs@openssh.com' is not supported by the server");
        }

        $realpath = $this->realpath($path);
        if ($realpath === false) {
            return false;
        }

        $packet = Strings::packSSH2('ss', 'statvfs@openssh.com', $realpath);
        $this->send_sftp_packet(NET_SFTP_EXTENDED, $packet);

        $response = $this->get_sftp_packet();
        if ($this->packet_type = SSH_FXP_EXTENDED_REPLY) {
            throw new \UnexpectedValueException('Expected SSH_FXP_EXTENDED_REPLY. '
                . 'Got packet type: ' . $this->packet_type);
        }

        /**
         * These requests return a SSH_FXP_STATUS reply on failure. On success they
         * return the following SSH_FXP_EXTENDED_REPLY reply:
         *
         * uint32        id
         * uint64        f_bsize     file system block size
         * uint64		f_frsize     fundamental fs block size
         * uint64		f_blocks     number of blocks (unit f_frsize)
         * uint64		f_bfree      free blocks in file system
         * uint64		f_bavail     free blocks for non-root
         * uint64		f_files      total file inodes
         * uint64		f_ffree      free file inodes
         * uint64		f_favail     free file inodes for to non-root
         * uint64		f_fsid       file system id
         * uint64		f_flag       bit mask of f_flag values
         * uint64		f_namemax    maximum filename length
         */
        list($bsize, $frsize, $blocks, $bfree, $bavail, $files, $ffree, $favail, $fsid, $flag, $namemax) =
            Strings::unpackSSH2('NQQQQQQQQQQQ', $response);

        return compact($id, $bsize, $frsize, $blocks, $bfree, $bavail, $files, $ffree, $favail, $fsid, $flag, $namemax);
    }
}
