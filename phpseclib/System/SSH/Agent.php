<?php

/**
 * Pure-PHP ssh-agent client.
 *
 * PHP version 5
 *
 * Here are some examples of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $agent = new \phpseclib\System\SSH\Agent();
 *
 *    $ssh = new \phpseclib\Net\SSH2('www.domain.tld');
 *    if (!$ssh->login('username', $agent)) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->exec('pwd');
 *    echo $ssh->exec('ls -la');
 * ?>
 * </code>
 *
 * @category  System
 * @package   SSH\Agent
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 * @internal  See http://api.libssh.org/rfc/PROTOCOL.agent
 */

namespace phpseclib\System\SSH;

use ParagonIE\ConstantTime\Base64;
use phpseclib\Crypt\RSA;
use phpseclib\Exception\BadConfigurationException;
use phpseclib\System\SSH\Agent\Identity;
use phpseclib\Common\Functions\Objects;

/**
 * Pure-PHP ssh-agent client identity factory
 *
 * requestIdentities() method pumps out \phpseclib\System\SSH\Agent\Identity objects
 *
 * @package SSH\Agent
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class Agent
{
    /**#@+
     * Message numbers
     *
     * @access private
     */
    // to request SSH1 keys you have to use SSH_AGENTC_REQUEST_RSA_IDENTITIES (1)
    const SSH_AGENTC_REQUEST_IDENTITIES = 11;
    // this is the SSH2 response; the SSH1 response is SSH_AGENT_RSA_IDENTITIES_ANSWER (2).
    const SSH_AGENT_IDENTITIES_ANSWER = 12;
    // the SSH1 request is SSH_AGENTC_RSA_CHALLENGE (3)
    const SSH_AGENTC_SIGN_REQUEST = 13;
    // the SSH1 response is SSH_AGENT_RSA_RESPONSE (4)
    const SSH_AGENT_SIGN_RESPONSE = 14;
    /**#@-*/

    /**@+
     * Agent forwarding status
     *
     * @access private
     */
    // no forwarding requested and not active
    const FORWARD_NONE = 0;
    // request agent forwarding when opportune
    const FORWARD_REQUEST = 1;
    // forwarding has been request and is active
    const FORWARD_ACTIVE = 2;
    /**#@-*/

    /**
     * Unused
     */
    const SSH_AGENT_FAILURE = 5;

    /**
     * Socket Resource
     *
     * @var resource
     * @access private
     */
    private $fsock;

    /**
     * Agent forwarding status
     *
     * @var int
     * @access private
     */
    private $forward_status = self::FORWARD_NONE;

    /**
     * Buffer for accumulating forwarded authentication
     * agent data arriving on SSH data channel destined
     * for agent unix socket
     *
     * @var string
     * @access private
     */
    private $socket_buffer = '';

    /**
     * Tracking the number of bytes we are expecting
     * to arrive for the agent socket on the SSH data
     * channel
     *
     * @var int
     * @access private
     */
    private $expected_bytes = 0;

    /**
     * The current request channel
     *
     * @var int
     * @access private
     */
    private $request_channel;

    /**
     * Default Constructor
     *
     * @return \phpseclib\System\SSH\Agent
     * @throws \phpseclib\Exception\BadConfigurationException if SSH_AUTH_SOCK cannot be found
     * @throws \RuntimeException on connection errors
     * @access public
     */
    public function __construct($address = null)
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
                    throw new BadConfigurationException('SSH_AUTH_SOCK not found');
            }
        }

        $this->fsock = fsockopen('unix://' . $address, 0, $errno, $errstr);
        if (!$this->fsock) {
            throw new \RuntimeException("Unable to connect to ssh-agent (Error $errno: $errstr)");
        }
    }

    /**
     * Request Identities
     *
     * See "2.5.2 Requesting a list of protocol 2 keys"
     * Returns an array containing zero or more \phpseclib\System\SSH\Agent\Identity objects
     *
     * @return array
     * @throws \RuntimeException on receipt of unexpected packets
     * @access public
     */
    public function requestIdentities()
    {
        if (!$this->fsock) {
            return [];
        }

        $packet = pack('NC', 1, self::SSH_AGENTC_REQUEST_IDENTITIES);
        if (strlen($packet) != fputs($this->fsock, $packet)) {
            throw new \RuntimeException('Connection closed while requesting identities');
        }

        $length = current(unpack('N', fread($this->fsock, 4)));
        $type = ord(fread($this->fsock, 1));
        if ($type != self::SSH_AGENT_IDENTITIES_ANSWER) {
            throw new \RuntimeException('Unable to request identities');
        }

        $identities = [];
        $keyCount = current(unpack('N', fread($this->fsock, 4)));
        for ($i = 0; $i < $keyCount; $i++) {
            $length = current(unpack('N', fread($this->fsock, 4)));
            $key_blob = fread($this->fsock, $length);
            $key_str = 'ssh-rsa ' . Base64::encode($key_blob);
            $length = current(unpack('N', fread($this->fsock, 4)));
            if ($length) {
                $key_str.= ' ' . fread($this->fsock, $length);
            }
            $length = current(unpack('N', substr($key_blob, 0, 4)));
            $key_type = substr($key_blob, 4, $length);
            switch ($key_type) {
                case 'ssh-rsa':
                    $key = new RSA();
                    $key->load($key_str);
                    break;
                case 'ssh-dss':
                    // not currently supported
                    break;
            }
            // resources are passed by reference by default
            if (isset($key)) {
                $identity = new Identity($this->fsock);
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
     * @param \phpseclib\Net\SSH2 $ssh
     * @return bool
     * @access public
     */
    public function startSSHForwarding($ssh)
    {
        if ($this->forward_status == self::FORWARD_NONE) {
            $this->forward_status = self::FORWARD_REQUEST;
        }
    }

    /**
     * Request agent forwarding of remote server
     *
     * @param \phpseclib\Net\SSH2 $ssh
     * @return bool
     * @access private
     */
    private function request_forwarding($ssh)
    {
        $this->request_channel = Objects::callFunc($ssh, 'get_open_channel');
        if ($this->request_channel === false) {
            return false;
        }

        $packet = pack(
            'CNNa*C',
            NET_SSH2_MSG_CHANNEL_REQUEST,
            Objects::getVar($ssh, 'server_channels')[$this->request_channel],
            strlen('auth-agent-req@openssh.com'),
            'auth-agent-req@openssh.com',
            1
        );

        $this->update_channel_status($ssh, NET_SSH2_MSG_CHANNEL_REQUEST);
        if (!Objects::callFunc($ssh, 'send_binary_packet', [$packet])) {
            return false;
        }

        $response = Objects::callFunc($ssh, 'get_channel_packet', [$this->request_channel]);
        if ($response === false) {
            return false;
        }

        $this->update_channel_status($ssh, NET_SSH2_MSG_CHANNEL_OPEN);
        $this->forward_status = self::FORWARD_ACTIVE;

        return true;
    }

    /**
     * On successful channel open
     *
     * This method is called upon successful channel
     * open to give the SSH Agent an opportunity
     * to take further action. i.e. request agent forwarding
     *
     * @param \phpseclib\Net\SSH2 $ssh
     * @access private
     */
    private function on_channel_open($ssh)
    {
        if ($this->forward_status == self::FORWARD_REQUEST) {
            $this->request_forwarding($ssh);
        }
    }

    /**
     * Forward data to SSH Agent and return data reply
     *
     * @param string $data
     * @return string Data from SSH Agent
     * @throws \RuntimeException on connection errors
     * @access private
     */
    private function forward_data($data)
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
            throw new \RuntimeException('Connection closed attempting to forward data to SSH agent');
        }

        $this->socket_buffer = '';
        $this->expected_bytes = 0;

        $agent_reply_bytes = current(unpack('N', fread($this->fsock, 4)));

        $agent_reply_data = fread($this->fsock, $agent_reply_bytes);
        $agent_reply_data = current(unpack('a*', $agent_reply_data));

        return pack('Na*', $agent_reply_bytes, $agent_reply_data);
    }

    /**
     * Forward data to SSH Agent and return data reply
     *
     * @param \phpseclib\Net\SSH2 $ssh
     * @param integer $status
     * @access private
     */
    private function update_channel_status($ssh, $status)
    {
        $temp = Objects::getVar($ssh, 'channel_status');
        $temp[$this->request_channel] = $status;
        Objects::setVar($ssh, 'channel_status', $temp);
    }
}
