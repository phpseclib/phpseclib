<?php

/**
 * Pure-PHP ssh-agent client.
 *
 * PHP versions 4 and 5
 *
 * Here are some examples of how to use this library:
 * <code>
 * <?php
 *    include 'System/SSH/Agent.php';
 *    include 'Net/SSH2.php';
 *
 *    $agent = new System_SSH_Agent();
 *
 *    $ssh = new Net_SSH2('www.domain.tld');
 *    if (!$ssh->login('username', $agent)) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->exec('pwd');
 *    echo $ssh->exec('ls -la');
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
 * @category  System
 * @package   System_SSH_Agent
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 * @internal  See http://api.libssh.org/rfc/PROTOCOL.agent
 */

/**#@+
 * Message numbers
 *
 * @access private
 */
// to request SSH1 keys you have to use SSH_AGENTC_REQUEST_RSA_IDENTITIES (1)
define('SYSTEM_SSH_AGENTC_REQUEST_IDENTITIES', 11);
// this is the SSH2 response; the SSH1 response is SSH_AGENT_RSA_IDENTITIES_ANSWER (2).
define('SYSTEM_SSH_AGENT_IDENTITIES_ANSWER', 12);
define('SYSTEM_SSH_AGENT_FAILURE', 5);
// the SSH1 request is SSH_AGENTC_RSA_CHALLENGE (3)
define('SYSTEM_SSH_AGENTC_SIGN_REQUEST', 13);
// the SSH1 response is SSH_AGENT_RSA_RESPONSE (4)
define('SYSTEM_SSH_AGENT_SIGN_RESPONSE', 14);
/**#@-*/

/**@+
 * Agent forwarding status
 *
 * @access private
 */
// no forwarding requested and not active
define('SYSTEM_SSH_AGENT_FORWARD_NONE', 0);
// request agent forwarding when opportune
define('SYSTEM_SSH_AGENT_FORWARD_REQUEST', 1);
// forwarding has been request and is active
define('SYSTEM_SSH_AGENT_FORWARD_ACTIVE', 2);
/**#@-*/

/**@+
 * Signature Flags
 *
 * See https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-5.3
 *
 * @access private
 */
define('SYSTEM_SSH_AGENT_RSA2_256', 2);
define('SYSTEM_SSH_AGENT_RSA2_512', 4);
/**#@-*/

/**
 * Pure-PHP ssh-agent client identity object
 *
 * Instantiation should only be performed by System_SSH_Agent class.
 * This could be thought of as implementing an interface that Crypt_RSA
 * implements. ie. maybe a Net_SSH_Auth_PublicKey interface or something.
 * The methods in this interface would be getPublicKey, setSignatureMode
 * and sign since those are the methods phpseclib looks for to perform
 * public key authentication.
 *
 * @package System_SSH_Agent
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  internal
 */
class System_SSH_Agent_Identity
{
    /**
     * Key Object
     *
     * @var Crypt_RSA
     * @access private
     * @see self::getPublicKey()
     */
    var $key;

    /**
     * Key Blob
     *
     * @var string
     * @access private
     * @see self::sign()
     */
    var $key_blob;

    /**
     * Socket Resource
     *
     * @var resource
     * @access private
     * @see self::sign()
     */
    var $fsock;

    /**
     * Signature flags
     *
     * @var int
     * @access private
     * @see self::sign()
     * @see self::setHash()
     */
    var $flags = 0;

    /**
     * Default Constructor.
     *
     * @param resource $fsock
     * @return System_SSH_Agent_Identity
     * @access private
     */
    function __construct($fsock)
    {
        $this->fsock = $fsock;
    }

    /**
     * PHP4 compatible Default Constructor.
     *
     * @see self::__construct()
     * @param resource $fsock
     * @access public
     */
    function System_SSH_Agent_Identity($fsock)
    {
        $this->__construct($fsock);
    }

    /**
     * Set Public Key
     *
     * Called by System_SSH_Agent::requestIdentities()
     *
     * @param Crypt_RSA $key
     * @access private
     */
    function setPublicKey($key)
    {
        $this->key = $key;
        $this->key->setPublicKey();
    }

    /**
     * Set Public Key
     *
     * Called by System_SSH_Agent::requestIdentities(). The key blob could be extracted from $this->key
     * but this saves a small amount of computation.
     *
     * @param string $key_blob
     * @access private
     */
    function setPublicKeyBlob($key_blob)
    {
        $this->key_blob = $key_blob;
    }

    /**
     * Get Public Key
     *
     * Wrapper for $this->key->getPublicKey()
     *
     * @param int $format optional
     * @return mixed
     * @access public
     */
    function getPublicKey($format = null)
    {
        return !isset($format) ? $this->key->getPublicKey() : $this->key->getPublicKey($format);
    }

    /**
     * Set Signature Mode
     *
     * Doesn't do anything as ssh-agent doesn't let you pick and choose the signature mode. ie.
     * ssh-agent's only supported mode is CRYPT_RSA_SIGNATURE_PKCS1
     *
     * @param int $mode
     * @access public
     */
    function setSignatureMode($mode)
    {
    }

    /**
     * Set Hash
     *
     * ssh-agent doesn't support using hashes for RSA other than SHA1
     *
     * @param string $hash
     * @access public
     */
    function setHash($hash)
    {
        $this->flags = 0;
        switch ($hash) {
            case 'sha1':
                break;
            case 'sha256':
                $this->flags = SYSTEM_SSH_AGENT_RSA2_256;
                break;
            case 'sha512':
                $this->flags = SYSTEM_SSH_AGENT_RSA2_512;
                break;
            default:
                user_error('The only supported hashes for RSA are sha1, sha256 and sha512');
        }
    }

    /**
     * Create a signature
     *
     * See "2.6.2 Protocol 2 private key signature request"
     *
     * @param string $message
     * @return string
     * @access public
     */
    function sign($message)
    {
        // the last parameter (currently 0) is for flags and ssh-agent only defines one flag (for ssh-dss): SSH_AGENT_OLD_SIGNATURE
        $packet = pack('CNa*Na*N', SYSTEM_SSH_AGENTC_SIGN_REQUEST, strlen($this->key_blob), $this->key_blob, strlen($message), $message, $this->flags);
        $packet = pack('Na*', strlen($packet), $packet);
        if (strlen($packet) != fputs($this->fsock, $packet)) {
            user_error('Connection closed during signing');
            return false;
        }

        $temp = fread($this->fsock, 4);
        if (strlen($temp) != 4) {
            user_error('Connection closed during signing');
            return false;
        }
        $length = current(unpack('N', $temp));
        $type = ord(fread($this->fsock, 1));
        if ($type != SYSTEM_SSH_AGENT_SIGN_RESPONSE) {
            user_error('Unable to retreive signature');
            return false;
        }

        $signature_blob = fread($this->fsock, $length - 1);
        if (strlen($signature_blob) != $length - 1) {
            user_error('Connection closed during signing');
            return false;
        }
        $length = current(unpack('N', $this->_string_shift($signature_blob, 4)));
        if ($length != strlen($signature_blob)) {
            user_error('Malformed signature blob');
            return false;
        }
        $length = current(unpack('N', $this->_string_shift($signature_blob, 4)));
        if ($length > strlen($signature_blob) + 4) {
            user_error('Malformed signature blob');
            return false;
        }
        $type = $this->_string_shift($signature_blob, $length);
        $this->_string_shift($signature_blob, 4);

        return $signature_blob;
    }

    /**
     * String Shift
     *
     * Inspired by array_shift
     *
     * @param string $string
     * @param int $index
     * @return string
     * @access private
     */
    function _string_shift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }
}

/**
 * Pure-PHP ssh-agent client identity factory
 *
 * requestIdentities() method pumps out System_SSH_Agent_Identity objects
 *
 * @package System_SSH_Agent
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class System_SSH_Agent
{
    /**
     * Socket Resource
     *
     * @var resource
     * @access private
     */
    var $fsock;

    /**
     * Agent forwarding status
     *
     * @access private
     */
    var $forward_status = SYSTEM_SSH_AGENT_FORWARD_NONE;

    /**
     * Buffer for accumulating forwarded authentication
     * agent data arriving on SSH data channel destined
     * for agent unix socket
     *
     * @access private
     */
    var $socket_buffer = '';

    /**
     * Tracking the number of bytes we are expecting
     * to arrive for the agent socket on the SSH data
     * channel
     */
    var $expected_bytes = 0;

    /**
     * Default Constructor
     *
     * @return System_SSH_Agent
     * @access public
     */
    function __construct($address = null)
    {
        if (!$address) {
            switch (true) {
                case isset($_SERVER['SSH_AUTH_SOCK']):
                    $address = $_SERVER['SSH_AUTH_SOCK'];
                    break;
                case isset($_ENV['SSH_AUTH_SOCK']):
                    $address = $_ENV['SSH_AUTH_SOCK'];
                    break;
                default:
                    user_error('SSH_AUTH_SOCK not found');
                    return false;
            }
        }

        $this->fsock = fsockopen('unix://' . $address, 0, $errno, $errstr);
        if (!$this->fsock) {
            user_error("Unable to connect to ssh-agent (Error $errno: $errstr)");
        }
    }

    /**
     * PHP4 compatible Default Constructor.
     *
     * @see self::__construct()
     * @access public
     */
    function System_SSH_Agent($address = null)
    {
        $this->__construct($address);
    }

    /**
     * Request Identities
     *
     * See "2.5.2 Requesting a list of protocol 2 keys"
     * Returns an array containing zero or more System_SSH_Agent_Identity objects
     *
     * @return array
     * @access public
     */
    function requestIdentities()
    {
        if (!$this->fsock) {
            return array();
        }

        $packet = pack('NC', 1, SYSTEM_SSH_AGENTC_REQUEST_IDENTITIES);
        if (strlen($packet) != fputs($this->fsock, $packet)) {
            user_error('Connection closed while requesting identities');
            return array();
        }

        $temp = fread($this->fsock, 4);
        if (strlen($temp) != 4) {
            user_error('Connection closed while requesting identities');
            return array();
        }
        $length = current(unpack('N', $temp));
        $type = ord(fread($this->fsock, 1));
        if ($type != SYSTEM_SSH_AGENT_IDENTITIES_ANSWER) {
            user_error('Unable to request identities');
            return array();
        }

        $identities = array();
        $temp = fread($this->fsock, 4);
        if (strlen($temp) != 4) {
            user_error('Connection closed while requesting identities');
            return array();
        }
        $keyCount = current(unpack('N', $temp));
        for ($i = 0; $i < $keyCount; $i++) {
            $temp = fread($this->fsock, 4);
            if (strlen($temp) != 4) {
                user_error('Connection closed while requesting identities');
                return array();
            }
            $length = current(unpack('N', $temp));
            $key_blob = fread($this->fsock, $length);
            if (strlen($key_blob) != $length) {
                user_error('Connection closed while requesting identities');
                return array();
            }
            $key_str = 'ssh-rsa ' . base64_encode($key_blob);
            $temp = fread($this->fsock, 4);
            if (strlen($temp) != 4) {
                user_error('Connection closed while requesting identities');
                return array();
            }
            $length = current(unpack('N', $temp));
            if ($length) {
                $temp = fread($this->fsock, $length);
                if (strlen($temp) != $length) {
                    user_error('Connection closed while requesting identities');
                    return array();
                }
                $key_str.= ' ' . $temp;
            }
            $length = current(unpack('N', substr($key_blob, 0, 4)));
            $key_type = substr($key_blob, 4, $length);
            switch ($key_type) {
                case 'ssh-rsa':
                    if (!class_exists('Crypt_RSA')) {
                        include_once 'Crypt/RSA.php';
                    }
                    $key = new Crypt_RSA();
                    $key->loadKey($key_str);
                    break;
                case 'ssh-dss':
                    // not currently supported
                    break;
            }
            // resources are passed by reference by default
            if (isset($key)) {
                $identity = new System_SSH_Agent_Identity($this->fsock);
                $identity->setPublicKey($key);
                $identity->setPublicKeyBlob($key_blob);
                $identities[] = $identity;
                unset($key);
            }
        }

        return $identities;
    }

    /**
     * Signal that agent forwarding should
     * be requested when a channel is opened
     *
     * @return bool
     * @access public
     */
    function startSSHForwarding()
    {
        if ($this->forward_status == SYSTEM_SSH_AGENT_FORWARD_NONE) {
            $this->forward_status = SYSTEM_SSH_AGENT_FORWARD_REQUEST;
        }
    }

    /**
     * Request agent forwarding of remote server
     *
     * @param Net_SSH2 $ssh
     * @return bool
     * @access private
     */
    function _request_forwarding($ssh)
    {
        $request_channel = $ssh->_get_open_channel();
        if ($request_channel === false) {
            return false;
        }

        $packet = pack(
            'CNNa*C',
            NET_SSH2_MSG_CHANNEL_REQUEST,
            $ssh->server_channels[$request_channel],
            strlen('auth-agent-req@openssh.com'),
            'auth-agent-req@openssh.com',
            1
        );

        $ssh->channel_status[$request_channel] = NET_SSH2_MSG_CHANNEL_REQUEST;

        if (!$ssh->_send_binary_packet($packet)) {
            return false;
        }

        $response = $ssh->_get_channel_packet($request_channel);
        if ($response === false) {
            return false;
        }

        $ssh->channel_status[$request_channel] = NET_SSH2_MSG_CHANNEL_OPEN;
        $this->forward_status = SYSTEM_SSH_AGENT_FORWARD_ACTIVE;

        return true;
    }

    /**
     * On successful channel open
     *
     * This method is called upon successful channel
     * open to give the SSH Agent an opportunity
     * to take further action. i.e. request agent forwarding
     *
     * @param Net_SSH2 $ssh
     * @access private
     */
    function _on_channel_open($ssh)
    {
        if ($this->forward_status == SYSTEM_SSH_AGENT_FORWARD_REQUEST) {
            $this->_request_forwarding($ssh);
        }
    }

    /**
     * Forward data to SSH Agent and return data reply
     *
     * @param string $data
     * @return data from SSH Agent
     * @access private
     */
    function _forward_data($data)
    {
        if ($this->expected_bytes > 0) {
            $this->socket_buffer.= $data;
            $this->expected_bytes -= strlen($data);
        } else {
            $agent_data_bytes = current(unpack('N', $data));
            $current_data_bytes = strlen($data);
            $this->socket_buffer = $data;
            if ($current_data_bytes != $agent_data_bytes + 4) {
                $this->expected_bytes = ($agent_data_bytes + 4) - $current_data_bytes;
                return false;
            }
        }

        if (strlen($this->socket_buffer) != fwrite($this->fsock, $this->socket_buffer)) {
            user_error('Connection closed attempting to forward data to SSH agent');
            return false;
        }

        $this->socket_buffer = '';
        $this->expected_bytes = 0;

        $temp = fread($this->fsock, 4);
        if (strlen($temp) != 4) {
            user_error('Connection closed while reading data response');
            return false;
        }
        $agent_reply_bytes = current(unpack('N', $temp));

        $agent_reply_data = fread($this->fsock, $agent_reply_bytes);
        if (strlen($agent_reply_data) != $agent_reply_bytes) {
            user_error('Connection closed while reading data response');
            return false;
        }
        $agent_reply_data = current(unpack('a*', $agent_reply_data));

        return pack('Na*', $agent_reply_bytes, $agent_reply_data);
    }
}
