<?php

/**
 * Pure-PHP ssh-agent client.
 *
 * {@internal See http://api.libssh.org/rfc/PROTOCOL.agent}
 *
 * PHP version 5
 *
 * Here are some examples of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $agent = new \phpseclib4\System\SSH\Agent();
 *
 *    $ssh = new \phpseclib4\Net\SSH2('www.domain.tld');
 *    if (!$ssh->login('username', $agent)) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->exec('pwd');
 *    echo $ssh->exec('ls -la');
 * ?>
 * </code>
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\System\SSH;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\Common\PublicKey;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Exception\BadConfigurationException;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\Net\SSH2;
use phpseclib4\System\SSH\Agent\Identity;

/**
 * Pure-PHP ssh-agent client identity factory
 *
 * requestIdentities() method pumps out \phpseclib4\System\SSH\Agent\Identity objects
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class Agent
{
    use Common\Traits\ReadBytes;

    // Message numbers

    // to request SSH1 keys you have to use SSH_AGENTC_REQUEST_RSA_IDENTITIES (1)
    public const SSH_AGENTC_REQUEST_IDENTITIES = 11;
    // this is the SSH2 response; the SSH1 response is SSH_AGENT_RSA_IDENTITIES_ANSWER (2).
    public const SSH_AGENT_IDENTITIES_ANSWER = 12;
    // the SSH1 request is SSH_AGENTC_RSA_CHALLENGE (3)
    public const SSH_AGENTC_SIGN_REQUEST = 13;
    // the SSH1 response is SSH_AGENT_RSA_RESPONSE (4)
    public const SSH_AGENT_SIGN_RESPONSE = 14;

    // Agent forwarding status

    // no forwarding requested and not active
    public const FORWARD_NONE = 0;
    // request agent forwarding when opportune
    public const FORWARD_REQUEST = 1;
    // forwarding has been request and is active
    public const FORWARD_ACTIVE = 2;

    /**
     * Unused
     */
    public const SSH_AGENT_FAILURE = 5;

    /**
     * Socket Resource
     *
     * @var resource
     */
    private $fsock;

    /**
     * Agent forwarding status
     *
     * @var int
     */
    private $forward_status = self::FORWARD_NONE;

    /**
     * Buffer for accumulating forwarded authentication
     * agent data arriving on SSH data channel destined
     * for agent unix socket
     *
     * @var string
     */
    private $socket_buffer = '';

    /**
     * Tracking the number of bytes we are expecting
     * to arrive for the agent socket on the SSH data
     * channel
     *
     * @var int
     */
    private $expected_bytes = 0;

    /**
     * Default Constructor
     *
     * @return Agent
     * @throws BadConfigurationException if SSH_AUTH_SOCK cannot be found
     * @throws RuntimeException on connection errors
     */
    public function __construct(?string $address = null)
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

        if (in_array('unix', stream_get_transports())) {
            $this->fsock = fsockopen('unix://' . $address, 0, $errno, $errstr);
            if (!$this->fsock) {
                throw new RuntimeException("Unable to connect to ssh-agent (Error $errno: $errstr)");
            }
        } else {
            if (substr($address, 0, 9) != '\\\\.\\pipe\\' || str_contains(substr($address, 9), '\\')) {
                throw new RuntimeException('Address is not formatted as a named pipe should be');
            }

            $this->fsock = fopen($address, 'r+b');
            if (!$this->fsock) {
                throw new RuntimeException('Unable to open address');
            }
        }
    }

    /**
     * Request Identities
     *
     * See "2.5.2 Requesting a list of protocol 2 keys"
     * Returns an array containing zero or more \phpseclib4\System\SSH\Agent\Identity objects
     *
     * @throws RuntimeException on receipt of unexpected packets
     */
    public function requestIdentities(): array
    {
        if (!$this->fsock) {
            return [];
        }

        $packet = pack('NC', 1, self::SSH_AGENTC_REQUEST_IDENTITIES);
        if (strlen($packet) != fwrite($this->fsock, $packet)) {
            throw new RuntimeException('Connection closed while requesting identities');
        }

        $length = current(unpack('N', $this->readBytes(4)));
        $packet = $this->readBytes($length);

        [$type, $keyCount] = Strings::unpackSSH2('CN', $packet);
        if ($type != self::SSH_AGENT_IDENTITIES_ANSWER) {
            throw new RuntimeException('Unable to request identities');
        }

        $identities = [];
        for ($i = 0; $i < $keyCount; $i++) {
            [$key_blob, $comment] = Strings::unpackSSH2('ss', $packet);
            $temp = $key_blob;
            [$key_type] = Strings::unpackSSH2('s', $temp);
            switch ($key_type) {
                case 'ssh-rsa':
                case 'ssh-dss':
                case 'ssh-ed25519':
                case 'ecdsa-sha2-nistp256':
                case 'ecdsa-sha2-nistp384':
                case 'ecdsa-sha2-nistp521':
                    $key = PublicKeyLoader::load($key_type . ' ' . base64_encode($key_blob));
            }
            // resources are passed by reference by default
            if (isset($key)) {
                $identity = (new Identity($this->fsock))
                    ->withPublicKey($key)
                    ->withPublicKeyBlob($key_blob)
                    ->withComment($comment);
                $identities[] = $identity;
                unset($key);
            }
        }

        return $identities;
    }

    /**
     * Returns the SSH Agent identity matching a given public key or null if no identity is found
     *
     * @return ?Identity
     */
    public function findIdentityByPublicKey(PublicKey $key)
    {
        $identities = $this->requestIdentities();
        $key = (string) $key;
        foreach ($identities as $identity) {
            if (((string) $identity->getPublicKey()) == $key) {
                return $identity;
            }
        }

        return null;
    }

    /**
     * Signal that agent forwarding should
     * be requested when a channel is opened
     */
    public function startSSHForwarding(): void
    {
        if ($this->forward_status == self::FORWARD_NONE) {
            $this->forward_status = self::FORWARD_REQUEST;
        }
    }

    /**
     * Request agent forwarding of remote server
     */
    private function request_forwarding(SSH2 $ssh): bool
    {
        if (!$ssh->requestAgentForwarding()) {
            return false;
        }

        $this->forward_status = self::FORWARD_ACTIVE;

        return true;
    }

    /**
     * On successful channel open
     *
     * This method is called upon successful channel
     * open to give the SSH Agent an opportunity
     * to take further action. i.e. request agent forwarding
     */
    public function registerChannelOpen(SSH2 $ssh): void
    {
        if ($this->forward_status == self::FORWARD_REQUEST) {
            $this->request_forwarding($ssh);
        }
    }

    /**
     * Forward data to SSH Agent and return data reply
     *
     * @return string Data from SSH Agent
     * @throws RuntimeException on connection errors
     */
    public function forwardData(string $data)
    {
        if ($this->expected_bytes > 0) {
            $this->socket_buffer .= $data;
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
            throw new RuntimeException('Connection closed attempting to forward data to SSH agent');
        }

        $this->socket_buffer = '';
        $this->expected_bytes = 0;

        $agent_reply_bytes = current(unpack('N', $this->readBytes(4)));

        $agent_reply_data = $this->readBytes($agent_reply_bytes);
        $agent_reply_data = current(unpack('a*', $agent_reply_data));

        return pack('Na*', $agent_reply_bytes, $agent_reply_data);
    }
}
