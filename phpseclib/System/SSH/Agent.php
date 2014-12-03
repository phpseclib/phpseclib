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
 * @category  System
 * @package   System_SSH_Agent
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright MMXIV Jim Wigginton
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

if (!class_exists('System_SSH_Agent_Identity')) {
    include_once 'Agent/Identity.php';
}

/**
 * Pure-PHP ssh-agent client identity factory
 *
 * requestIdentities() method pumps out System_SSH_Agent_Identity objects
 *
 * @package System_SSH_Agent
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  internal
 */
class System_SSH_Agent
{
    /**
     * Socket Resource
     *
     * @var Resource
     * @access private
     */
    var $fsock;

    /**
     * Default Constructor
     *
     * @return System_SSH_Agent
     * @access public
     */
    function __construct()
    {
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

        $this->fsock = fsockopen('unix://' . $address, 0, $errno, $errstr);
        if (!$this->fsock) {
            user_error("Unable to connect to ssh-agent (Error $errno: $errstr)");
        }
    }

    /**
     * Request Identities
     *
     * See "2.5.2 Requesting a list of protocol 2 keys"
     * Returns an array containing zero or more System_SSH_Agent_Identity objects
     *
     * @return Array
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
        }

        $length = current(unpack('N', fread($this->fsock, 4)));
        $type = ord(fread($this->fsock, 1));
        if ($type != SYSTEM_SSH_AGENT_IDENTITIES_ANSWER) {
            user_error('Unable to request identities');
        }

        $identities = array();
        $keyCount = current(unpack('N', fread($this->fsock, 4)));
        for ($i = 0; $i < $keyCount; $i++) {
            $length = current(unpack('N', fread($this->fsock, 4)));
            $key_blob = fread($this->fsock, $length);
            $length = current(unpack('N', fread($this->fsock, 4)));
            $key_comment = fread($this->fsock, $length);
            $length = current(unpack('N', substr($key_blob, 0, 4)));
            $key_type = substr($key_blob, 4, $length);
            switch ($key_type) {
                case 'ssh-rsa':
                    if (!class_exists('Crypt_RSA')) {
                        include_once 'Crypt/RSA.php';
                    }
                    $key = new Crypt_RSA();
                    $key->loadKey('ssh-rsa ' . base64_encode($key_blob) . ' ' . $key_comment);
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
}
