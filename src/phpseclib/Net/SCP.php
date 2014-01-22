<?php

/**
 * Pure-PHP implementation of SCP.
 *
 * PHP versions 4 and 5
 *
 * The API for this library is modeled after the API from PHP's {@link http://php.net/book.ftp FTP extension}.
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include('Net/SCP.php');
 *    include('Net/SSH2.php');
 *
 *    $ssh = new Net\SSH2('www.domain.tld');
 *    if (!$ssh->login('username', 'password')) {
 *        exit('bad login');
 *    }

 *    $scp = new Net\SCP($ssh);
 *    $scp->put('abcd', str_repeat('x', 1024*1024));
 * ?>
 * </code>
 *
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @category  Net
 * @package   Net\SCP
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright MMX Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Net;

use phpseclib\NET\SCP,
    phpseclib\NET\SSH1,
    phpseclib\NET\SSH2;

/**
 * Pure-PHP implementations of SCP.
 *
 * @package Net\SCP
 * @author  Jim Wigginton <terrafrost@php.net>
 * @version 0.1.0
 * @access  public
 */
class SCP
{
    /**
     * Reads data from a local file.
     */
    const LOCAL_FILE = 1;
    
    /**
     * Reads data from a string.
     */
    const STRING = 2;
    
    /**
     * SSH1 is being used.
     */
    const SSH1 = 1;
    
    /**
     * SSH2 is being used.
     */
    const SSH2 = 2;
    
    /**
     * SSH Object
     *
     * @var Object
     * @access private
     */
    private $ssh;

    /**
     * Packet Size
     *
     * @var Integer
     * @access private
     */
    private $packet_size;

    /**
     * Mode
     *
     * @var Integer
     * @access private
     */
    private $mode;

    /**
     * Default Constructor.
     *
     * Connects to an SSH server
     *
     * @param String $host
     * @param optional Integer $port
     * @param optional Integer $timeout
     * @return Net\SCP
     * @access public
     */
    public function __construct($ssh)
    {
        if (!is_object($ssh)) {
            return;
        }
        
        switch (get_class($ssh)) {
            case 'phpseclib\Net\SSH2':
                $this->mode = SCP::SSH2;
                break;
            case 'phpseclib\Net\SSH1':
                $this->packet_size = 50000;
                $this->mode = SCP::SSH1;
                break;
            default:
                return;
        }

        $this->ssh = $ssh;
    }

    /**
     * Uploads a file to the SCP server.
     *
     * By default, Net\SCP::put() does not read from the local filesystem.  $data is dumped directly into $remote_file.
     * So, for example, if you set $data to 'filename.ext' and then do Net\SCP::get(), you will get a file, twelve bytes
     * long, containing 'filename.ext' as its contents.
     *
     * Setting $mode to SCP::LOCAL_FILE will change the above behavior.  With SCP::LOCAL_FILE, $remote_file will 
     * contain as many bytes as filename.ext does on your local filesystem.  If your filename.ext is 1MB then that is how
     * large $remote_file will be, as well.
     *
     * Currently, only binary mode is supported.  As such, if the line endings need to be adjusted, you will need to take
     * care of that, yourself.
     *
     * @param String $remote_file
     * @param String $data
     * @param optional Integer $mode
     * @param optional Callable $callback
     * @return Boolean
     * @access public
     */
    public function put($remote_file, $data, $mode = SCP::STRING, $callback = null)
    {
        if (!isset($this->ssh)) {
            return false;
        }

        if (!$this->ssh->exec('scp -t ' . $remote_file, false)) { // -t = to
            return false;
        }

        $temp = $this->_receive();
        if ($temp !== chr(0)) {
            return false;
        }

        if ($this->mode == SCP::SSH2) {
            $this->packet_size = $this->ssh->packet_size_client_to_server[SSH2::CHANNEL_EXEC] - 4;
        }

        $remote_file = basename($remote_file);

        if ($mode == SCP::STRING) {
            $size = strlen($data);
        } else {
            if (!is_file($data)) {
                user_error("$data is not a valid file", E_USER_NOTICE);
                return false;
            }

            $fp = @fopen($data, 'rb');
            if (!$fp) {
                fclose($fp);
                return false;
            }
            $size = filesize($data);
        }

        $this->_send('C0644 ' . $size . ' ' . $remote_file . "\n");

        $temp = $this->_receive();
        if ($temp !== chr(0)) {
            return false;
        }

        $sent = 0;
        while ($sent < $size) {
            $temp = $mode & SCP::STRING ? substr($data, $sent, $this->packet_size) : fread($fp, $this->packet_size);
            $this->_send($temp);
            $sent+= strlen($temp);

            if (is_callable($callback)) {
                $callback($sent);
            }
        }
        $this->_close();

        if ($mode != SCP::STRING) {
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
     * @param String $remote_file
     * @param optional String $local_file
     * @return Mixed
     * @access public
     */
    public function get($remote_file, $local_file = false)
    {
        if (!isset($this->ssh)) {
            return false;
        }

        if (!$this->ssh->exec('scp -f ' . $remote_file, false)) { // -f = from
            return false;
        }

        $this->_send("\0");

        if (!preg_match('#(?<perms>[^ ]+) (?<size>\d+) (?<name>.+)#', rtrim($this->_receive()), $info)) {
            return false;
        }

        $this->_send("\0");

        $size = 0;

        if ($local_file !== false) {
            $fp = @fopen($local_file, 'wb');
            if (!$fp) {
                return false;
            }
        }
        
        $content = '';
        while ($size < $info['size']) {
            $data = $this->_receive();
            // SCP usually seems to split stuff out into 16k chunks
            $size+= strlen($data);

            if ($local_file === false) {
                $content.= $data;
            } else {
                fputs($fp, $data);
            }
        }

        $this->_close();

        if ($local_file !== false) {
            fclose($fp);
            return true;
        }
        
        return $content;
    }

    /**
     * Sends a packet to an SSH server
     *
     * @param String $data
     * @access private
     */
    private function _send($data)
    {
        switch ($this->mode) {
            case SCP::SSH2:
                $this->ssh->_send_channel_packet(SSH2::CHANNEL_EXEC, $data);
                break;
            case SCP::SSH1:
                $data = pack('CNa*', SSH1::CMSG_STDIN_DATA, strlen($data), $data);
                $this->ssh->_send_binary_packet($data);
         }
    }

    /**
     * Receives a packet from an SSH server
     *
     * @return String
     * @access private
     */
    private function _receive()
    {
        switch ($this->mode) {
            case SCP::SSH2:
                return $this->ssh->_get_channel_packet(SSH2::CHANNEL_EXEC, true);
            case SCP::SSH1:
                if (!$this->ssh->bitmap) {
                    return false;
                }
                while (true) {
                    $response = $this->ssh->_get_binary_packet();
                    switch ($response[SSH1::RESPONSE_TYPE]) {
                        case SSH1::SMSG_STDOUT_DATA:
                            extract(unpack('Nlength', $response[SSH1::RESPONSE_DATA]));
                            return $this->ssh->_string_shift($response[SSH1::RESPONSE_DATA], $length);
                        case SSH1::SMSG_STDERR_DATA:
                            break;
                        case SSH1::SMSG_EXITSTATUS:
                            $this->ssh->_send_binary_packet(chr(SSH1::CMSG_EXIT_CONFIRMATION));
                            fclose($this->ssh->fsock);
                            $this->ssh->bitmap = 0;
                            return false;
                        default:
                            user_error('Unknown packet received', E_USER_NOTICE);
                            return false;
                    }
                }
         }
    }

    /**
     * Closes the connection to an SSH server
     *
     * @access private
     */
    private function _close()
    {
        switch ($this->mode) {
            case SCP::SSH2:
                $this->ssh->_close_channel(SSH2::CHANNEL_EXEC, true);
                break;
            case SCP::SSH1:
                $this->ssh->disconnect();
         }
    }
}
