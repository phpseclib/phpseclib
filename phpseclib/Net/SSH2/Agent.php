<?php
/*
 * Pure-PHP implementation of SSH-Agent.
 *
 * PHP versions 4 and 5
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
 * @category   Net
 * @package    Net_SSH2
 * @author     Manuel 'Kea' Baldassarri <k3a@k3a.it>
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @version    $Id: SSH2_Agent.php,v 1.0 2012-08-09 09:46:00 kea Exp $
 * @link       http://phpseclib.sourceforge.net
 */

define('NET_SSH2_AGENTC_REQUEST_IDENTITIES', 11);
define('NET_SSH2_AGENT_IDENTITIES_ANSWER', 12);
define('NET_SSH2_AGENTC_SIGN_REQUEST',13);
define('NET_SSH2_AGENT_SIGN_RESPONSE',14);

define('NET_SSH2_AGENTC_LOCK',22); // SSH_AGENTC_LOCK
define('NET_SSH2_AGENTC_UNLOCK',23); // SSH_AGENTC_UNLOCK

define('NET_SSH2_AGENTC_REQUEST_RSA_IDENTITIES', 1); // SSH_AGENTC_REQUEST_RSA_IDENTITIES
define('NET_SSH2_AGENT_RSA_IDENTITIES_ANSWER', 2); // SSH_AGENT_RSA_IDENTITIES_ANSWER
define('NET_SSH2_AGENT_FAILURE', 5); // SSH_AGENT_FAILURE

/**
 *
 */
class Net_SSH2_Agent
{
    var $socket = null;
    var $keys = array();
    var $ssh;

    function Net_SSH2_Agent($ssh)
    {
      $this->ssh = $ssh;
    }

    function connect()
    {
      $socket = socket_create(AF_UNIX, SOCK_STREAM, 0);
      $address = null;

      if (isset($_SERVER['SSH_AUTH_SOCK'])) {
        $address = $_SERVER['SSH_AUTH_SOCK'];
      } elseif (isset($_ENV['SSH_AUTH_SOCK'])) {
        $address = $_ENV['SSH_AUTH_SOCK'];
      } else {
        user_error('SSH_AUTH_SOCK not found.', E_USER_NOTICE);

        return false;
      }

      if (is_null($address) || !socket_connect($socket, $address)) {
        user_error('Unable to connect '.socket_strerror(socket_last_error()), E_USER_NOTICE);

        return false;
      }

      return $this->socket = $socket;
    }

    function requestIdentities()
    {
        if (!$this->sendRequest(NET_SSH2_AGENTC_REQUEST_IDENTITIES)) {
          echo 'Unable to request identities '.socket_strerror(socket_last_error());

          return false;
        }

        $bufferLenght = $this->readLength();
        $type = $this->readType();

        if ($type == NET_SSH2_AGENT_FAILURE) {

            return false;
        } elseif ($type != NET_SSH2_AGENT_RSA_IDENTITIES_ANSWER && $type != NET_SSH2_AGENT_IDENTITIES_ANSWER) {
            // throw new \Exception("Unknown response from agent: $type");
            return false;
        }

        $buffer = socket_read($this->socket, $bufferLenght - 1);
        $keysCount = $this->binaryToLong($buffer);
        $buffer = substr($buffer, 4);

        for ($i = 0; $i < $keysCount; ++$i) {
            $blob = $this->readPacketFromBuffer($buffer);
            $this->keys[] = array(
                                  'blob' => $blob,
                                  'comment' => $this->readPacketFromBuffer($buffer),
                                  'key' => 'ssh-rsa '.base64_encode($blob));
        }
    }

    static function binaryToLong($binary)
    {

        return current(unpack('Nlong', $binary));
    }

    function sendRequest($type, $data = '')
    {
        $len = strlen($data) + 1;
        $buffer = pack("NCa*", $len, $type, $data);

        return socket_write($this->socket, $buffer);
    }

    function readLength()
    {
        $len = socket_read($this->socket, 4);

        return $this->binaryToLong($len);
    }

    function readType()
    {

        return ord(socket_read($this->socket, 1));
    }

    function readPacketFromBuffer(&$buffer)
    {
        $len = $this->binaryToLong($buffer);
        $packet = substr($buffer, 4, $len);
        $buffer = substr($buffer, $len + 4);

        return $packet;
    }

    function getKeys()
    {

        return $this->keys;
    }

    function socket_can_write($socket)
    {
        $write = array($socket);
        $n = null;
        socket_select($n, $write, $n, 0);

        return (isset($write[0]) && $write[0] === $socket);
    }

    function sign($pubkeydata, $data)
    {
        /* Create a request to sign the data */
        $s = pack('CNa*Na*N',
                NET_SSH2_AGENTC_SIGN_REQUEST,
                strlen($pubkeydata),
                $pubkeydata,
                strlen($data),
                $data,
                0);

        if (!$this->socket_can_write($this->socket)) {
            // throw new Exception("Agent not connected");
            return false;
        }

        $rc = socket_write($this->socket, pack("Na*", strlen($s), $s));

        if ($rc === false) {
            // throw new Exception('Unable to write to the socket: '.socket_strerror(socket_last_error()));
            return false;
        }

        $len = $this->readLength();

        if ($len < 8) {
            // throw new Exception("Error protocol");
            return false;
        }

        $type = $this->readType();

        if ($type != NET_SSH2_AGENT_SIGN_RESPONSE) {
            // throw new Exception("Error protocol");
            return false;
        }

        $s = socket_read($this->socket, $len - 1);

        $signature = unpack('Nlen/a*blob', $s);

        if ($len != 5 + $signature['len']) {
            // throw new Exception("Invalid sign");
            return false;
        }

        return $signature['blob'];
    }
}
