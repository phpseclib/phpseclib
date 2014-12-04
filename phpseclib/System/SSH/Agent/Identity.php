<?php
/**
 * Pure-PHP ssh-agent client.
 *
 * PHP versions 4 and 5
 *
 * @category  System
 * @package   System_SSH_Agent
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright MMXIV Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 * @internal  See http://api.libssh.org/rfc/PROTOCOL.agent
 */

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
     * @see System_SSH_Agent_Identity::getPublicKey()
     */
    var $key;

    /**
     * Key Blob
     *
     * @var String
     * @access private
     * @see System_SSH_Agent_Identity::sign()
     */
    var $key_blob;

    /**
     * Socket Resource
     *
     * @var Resource
     * @access private
     * @see System_SSH_Agent_Identity::sign()
     */
    var $fsock;

    /**
     * Default Constructor.
     *
     * @param Resource $fsock
     * @return System_SSH_Agent_Identity
     * @access private
     */
    function __construct($fsock)
    {
        $this->fsock = $fsock;
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
     * @param String $key_blob
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
     * @param Integer $format optional
     * @return Mixed
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
     * @param Integer $mode
     * @access public
     */
    function setSignatureMode($mode)
    {
    }

    /**
     * Create a signature
     *
     * See "2.6.2 Protocol 2 private key signature request"
     *
     * @param String $message
     * @return String
     * @access public
     */
    function sign($message)
    {
        // the last parameter (currently 0) is for flags and ssh-agent only defines one flag (for ssh-dss): SSH_AGENT_OLD_SIGNATURE
        $packet = pack('CNa*Na*N', System_SSH_Agent::SYSTEM_SSH_AGENTC_SIGN_REQUEST, strlen($this->key_blob), $this->key_blob, strlen($message), $message, 0);
        $packet = pack('Na*', strlen($packet), $packet);
        if (strlen($packet) != fputs($this->fsock, $packet)) {
            user_error('Connection closed during signing');
        }

        $length = current(unpack('N', fread($this->fsock, 4)));
        $type = ord(fread($this->fsock, 1));
        if ($type != System_SSH_Agent::SYSTEM_SSH_AGENT_SIGN_RESPONSE) {
            user_error('Unable to retreive signature');
        }

        $signature_blob = fread($this->fsock, $length - 1);
        // the only other signature format defined - ssh-dss - is the same length as ssh-rsa
        // the + 12 is for the other various SSH added length fields
        return substr($signature_blob, strlen('ssh-rsa') + 12);
    }
}
