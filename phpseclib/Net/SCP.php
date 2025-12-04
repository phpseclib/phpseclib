<?php

/**
 * Pure-PHP implementation of SCP.
 *
 * PHP version 5
 *
 * The API for this library is modeled after the API from PHP's {@link http://php.net/book.ftp FTP extension}.
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $scp = new \phpseclib3\Net\SCP('www.domain.tld');
 *    if (!$scp->login('username', 'password')) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $scp->exec('pwd') . "\r\n";
 *    $scp->put('filename.ext', 'hello, world!');
 *    echo $scp->exec('ls -latr');
 * ?>
 * </code>
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib4\Net;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Exception\FileNotFoundException;

/**
 * Pure-PHP implementations of SCP.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class SCP extends SSH2
{
    /**
     * Reads data from a local file.
     *
     * @see \phpseclib3\Net\SCP::put()
     */
    const SOURCE_LOCAL_FILE = 1;
    /**
     * Reads data from a string.
     *
     * @see \phpseclib3\Net\SCP::put()
     */
    // this value isn't really used anymore but i'm keeping it reserved for historical reasons
    const SOURCE_STRING = 2;
    /**
     * SCP.php doesn't support SOURCE_CALLBACK because, with that one, we don't know the size, in advance
     */
    //const SOURCE_CALLBACK = 16;

    /**
     * Error information
     *
     * @see self::getSCPErrors()
     * @see self::getLastSCPError()
     */
    private array $scp_errors = [];

    /**
     * Uploads a file to the SCP server.
     *
     * By default, \phpseclib\Net\SCP::put() does not read from the local filesystem.  $data is dumped directly into $remote_file.
     * So, for example, if you set $data to 'filename.ext' and then do \phpseclib\Net\SCP::get(), you will get a file, twelve bytes
     * long, containing 'filename.ext' as its contents.
     *
     * Setting $mode to self::SOURCE_LOCAL_FILE will change the above behavior.  With self::SOURCE_LOCAL_FILE, $remote_file will
     * contain as many bytes as filename.ext does on your local filesystem.  If your filename.ext is 1MB then that is how
     * large $remote_file will be, as well.
     *
     * Currently, only binary mode is supported.  As such, if the line endings need to be adjusted, you will need to take
     * care of that, yourself.
     * 
     * @param string|resource $data
     */
    public function put(string $remote_file, mixed $data, int $mode = self::SOURCE_STRING, ?callable $callback = null): bool
    {
        if (!($this->bitmap & self::MASK_LOGIN)) {
            return false;
        }

        if (empty($remote_file)) {
            // remote file cannot be blank
            return false;
        }

        if (!$this->exec('scp -t ' . escapeshellarg($remote_file), false)) { // -t = to
            return false;
        }

        $temp = $this->get_channel_packet(self::CHANNEL_EXEC, true);
        if ($temp !== chr(0)) {
            $this->close_channel(self::CHANNEL_EXEC, true);
            return false;
        }

        $packet_size = $this->packet_size_client_to_server[self::CHANNEL_EXEC] - 4;

        $remote_file = basename($remote_file);

        $dataCallback = false;
        switch (true) {
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
                    $this->close_channel(self::CHANNEL_EXEC, true);
                    return false;
                }
        }

        if (isset($fp)) {
            $stat = fstat($fp);
            $size = !empty($stat) ? $stat['size'] : 0;
        } else {
            $size = strlen($data);
        }

        $sent = 0;
        $size = $size < 0 ? ($size & 0x7FFFFFFF) + 0x80000000 : $size;

        $temp = 'C0644 ' . $size . ' ' . $remote_file . "\n";
        $this->send_channel_packet(self::CHANNEL_EXEC, $temp);

        $temp = $this->get_channel_packet(self::CHANNEL_EXEC, true);
        if ($temp !== chr(0)) {
            $this->close_channel(self::CHANNEL_EXEC, true);
            return false;
        }

        $sent = 0;
        while ($sent < $size) {
            $temp = $mode & self::SOURCE_STRING ? substr($data, $sent, $packet_size) : fread($fp, $packet_size);
            $this->send_channel_packet(self::CHANNEL_EXEC, $temp);
            $sent+= strlen($temp);

            if (is_callable($callback)) {
                call_user_func($callback, $sent);
            }
        }
        $this->close_channel(self::CHANNEL_EXEC, true);

        if ($mode != self::SOURCE_STRING) {
            fclose($fp);
        }

        return true;
    }

    /**
     * Downloads a file from the SCP server.
     *
     * Returns a string containing the contents of $remote_file if $local_file is left undefined or a boolean false if
     * the operation was unsuccessful.  If $local_file is defined, returns true or false depending on the success of the
     * operation
     *
     * @param string|resource|null $local_file
     */
    function get(string $remote_file, mixed $local_file = null, ?callable $progressCallback = null): bool|string
    {
        if (!($this->bitmap & self::MASK_LOGIN)) {
            return false;
        }

        if (!$this->exec('scp -f ' . escapeshellarg($remote_file), false)) { // -f = from
            return false;
        }

        $this->send_channel_packet(self::CHANNEL_EXEC, chr(0));

        $info = $this->get_channel_packet(self::CHANNEL_EXEC, true);
        // per https://goteleport.com/blog/scp-familiar-simple-insecure-slow/ non-zero responses mean there are errors
        if ($info[0] === chr(1) || $info[0] == chr(2)) {
            $type = $info[0] === chr(1) ? 'warning' : 'error';
            $this->scp_errors[] = "$type: " . substr($info, 1);
            $this->close_channel(self::CHANNEL_EXEC, true);
            return false;
        }

        $this->send_channel_packet(self::CHANNEL_EXEC, chr(0));

        if (!preg_match('#(?<perms>[^ ]+) (?<size>\d+) (?<name>.+)#', rtrim($info), $info)) {
            $this->close_channel(self::CHANNEL_EXEC, true);
            return false;
        }

        $fclose_check = false;
        if (is_resource($local_file)) {
            $fp = $local_file;
        } elseif (!is_null($local_file)) {
            $fp = @fopen($local_file, 'wb');
            if (!$fp) {
                $this->close_channel(self::CHANNEL_EXEC, true);
                return false;
            }
            $fclose_check = true;
        } else {
            $content = '';
        }

        $size = 0;
        while (true) {
            $data = $this->get_channel_packet(self::CHANNEL_EXEC, true);
            // Terminate the loop in case the server repeatedly sends an empty response
            if ($data === false) {
                $this->close_channel(self::CHANNEL_EXEC, true);
                // no data received from server
                return false;
            }
            // SCP usually seems to split stuff out into 16k chunks
            $length = strlen($data);
            $size+= $length;
            $end = $size > $info['size'];
            if ($end) {
                $diff = $size - $info['size'];
                $offset = $length - $diff;
                if ($data[$offset] === chr(0)) {
                    $data = substr($data, 0, -$diff);
                } else {
                    $type = $data[$offset] === chr(1) ? 'warning' : 'error';
                    $this->scp_errors[] = "$type: " . substr($data, 1);
                    $this->close_channel(self::CHANNEL_EXEC, true);
                    return false;
                }
            }

            if (is_null($local_file)) {
                $content.= $data;
            } else {
                fputs($fp, $data);
            }

            if (is_callable($progressCallback)) {
                call_user_func($progressCallback, $size);
            }

            if ($end) {
                break;
            }
        }

        $this->close_channel(self::CHANNEL_EXEC, true);

        if ($fclose_check) {
            fclose($fp);
        }

        // if $content isn't set that means a file was written to
        return isset($content) ? $content : true;
    }

    /**
     * Returns all errors on the SCP layer
     */
    public function getSCPErrors(): array
    {
        return $this->scp_errors;
    }

    /**
     * Returns the last error on the SCP layer
     */
    public function getLastSCPError(): string
    {
        return count($this->scp_errors) ? $this->scp_errors[count($this->scp_errors) - 1] : '';
    }
}
