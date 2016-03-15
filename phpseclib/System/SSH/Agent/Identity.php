<?php
/**
 * Pure-PHP ssh-agent client.
 *
 * PHP version 5
 *
 * @category  System
 * @package   SSH\Agent
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 * @internal  See http://api.libssh.org/rfc/PROTOCOL.agent
 */

namespace phpseclib\System\SSH\Agent;

use phpseclib\Crypt\RSA;
use phpseclib\Exception\UnsupportedAlgorithmException;
use phpseclib\System\SSH\Agent;

/**
 * Pure-PHP ssh-agent client identity object
 *
 * Instantiation should only be performed by \phpseclib\System\SSH\Agent class.
 * This could be thought of as implementing an interface that phpseclib\Crypt\RSA
 * implements. ie. maybe a Net_SSH_Auth_PublicKey interface or something.
 * The methods in this interface would be getPublicKey and sign since those are the
 * methods phpseclib looks for to perform public key authentication.
 *
 * @package SSH\Agent
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  internal
 */
class Identity
{
    /**
     * Key Object
     *
     * @var \phpseclib\Crypt\RSA
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
     * Default Constructor.
     *
     * @param resource $fsock
     * @return \phpseclib\System\SSH\Agent\Identity
     * @access private
     */
    function __construct($fsock)
    {
        $this->fsock = $fsock;
    }

    /**
     * Set Public Key
     *
     * Called by \phpseclib\System\SSH\Agent::requestIdentities()
     *
     * @param \phpseclib\Crypt\RSA $key
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
     * Called by \phpseclib\System\SSH\Agent::requestIdentities(). The key blob could be extracted from $this->key
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
     * @param int $type optional
     * @return mixed
     * @access public
     */
    function getPublicKey($type = 'PKCS8')
    {
        return $this->key->getPublicKey($type);
    }

    /**
     * Sets the hash
     *
     * ssh-agent only supports signatures with sha1 hashes but to maintain BC with RSA.php this function exists
     *
     * @param string $hash optional
     * @throws \phpseclib\Exception\UnsupportedAlgorithmException if the algorithm is unsupported
     * @access public
     */
    function setHash($hash = 'sha1')
    {
        if ($hash != 'sha1') {
            throw new UnsupportedAlgorithmException('ssh-agent can only be used with the sha1 hash');
        }
    }

    /**
     * Create a signature
     *
     * See "2.6.2 Protocol 2 private key signature request"
     *
     * @param string $message
     * @param int $padding optional
     * @return string
     * @throws \RuntimeException on connection errors
     * @throws \phpseclib\Exception\UnsupportedAlgorithmException if the algorithm is unsupported
     * @access public
     */
    function sign($message, $padding = RSA::PADDING_PKCS1)
    {
        if ($padding != RSA::PADDING_PKCS1 && $padding != RSA::PADDING_RELAXED_PKCS1) {
            throw new UnsupportedAlgorithmException('ssh-agent can only create PKCS1 signatures');
        }

        // the last parameter (currently 0) is for flags and ssh-agent only defines one flag (for ssh-dss): SSH_AGENT_OLD_SIGNATURE
        $packet = pack('CNa*Na*N', Agent::SSH_AGENTC_SIGN_REQUEST, strlen($this->key_blob), $this->key_blob, strlen($message), $message, 0);
        $packet = pack('Na*', strlen($packet), $packet);
        if (strlen($packet) != fputs($this->fsock, $packet)) {
            throw new \RuntimeException('Connection closed during signing');
        }

        $length = current(unpack('N', fread($this->fsock, 4)));
        $type = ord(fread($this->fsock, 1));
        if ($type != Agent::SSH_AGENT_SIGN_RESPONSE) {
            throw new \RuntimeException('Unable to retreive signature');
        }

        $signature_blob = fread($this->fsock, $length - 1);
        // the only other signature format defined - ssh-dss - is the same length as ssh-rsa
        // the + 12 is for the other various SSH added length fields
        return substr($signature_blob, strlen('ssh-rsa') + 12);
    }
}
