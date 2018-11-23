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
use phpseclib\Common\Functions\Strings;

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
    /**@+
     * Signature Flags
     *
     * See https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-5.3
     *
     * @access private
     */
    const SSH_AGENT_RSA2_256 = 2;
    const SSH_AGENT_RSA2_512 = 4;
    /**#@-*/

    /**
     * Key Object
     *
     * @var \phpseclib\Crypt\RSA
     * @access private
     * @see self::getPublicKey()
     */
    private $key;

    /**
     * Key Blob
     *
     * @var string
     * @access private
     * @see self::sign()
     */
    private $key_blob;

    /**
     * Socket Resource
     *
     * @var resource
     * @access private
     * @see self::sign()
     */
    private $fsock;

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
     * @return \phpseclib\System\SSH\Agent\Identity
     * @access private
     */
    public function __construct($fsock)
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
    public function setPublicKey($key)
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
    public function setPublicKeyBlob($key_blob)
    {
        $this->key_blob = $key_blob;
    }

    /**
     * Get Public Key
     *
     * Wrapper for $this->key->getPublicKey()
     *
     * @param string $type optional
     * @return mixed
     * @access public
     */
    public function getPublicKey($type = 'PKCS8')
    {
        return $this->key->getPublicKey($type);
    }

    /**
     * Sets the hash
     *
     * ssh-agent only supports signatures with sha1 hashes but to maintain BC with RSA.php this function exists
     *
     * @param string $hash optional
     * @access public
     */
    public function setHash($hash)
    {
        $this->flags = 0;
        switch ($hash) {
            case 'sha1':
                break;
            case 'sha256':
                $this->flags = self::SSH_AGENT_RSA2_256;
                break;
            case 'sha512':
                $this->flags = self::SSH_AGENT_RSA2_512;
                break;
            default:
                throw new UnsupportedAlgorithmException('The only supported hashes for RSA are sha1, sha256 and sha512');
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
    public function sign($message, $padding = RSA::PADDING_PKCS1)
    {
        if ($padding != RSA::PADDING_PKCS1 && $padding != RSA::PADDING_RELAXED_PKCS1) {
            throw new UnsupportedAlgorithmException('ssh-agent can only create PKCS1 signatures');
        }

        // the last parameter (currently 0) is for flags and ssh-agent only defines one flag (for ssh-dss): SSH_AGENT_OLD_SIGNATURE
        $packet = pack('CNa*Na*N', Agent::SSH_AGENTC_SIGN_REQUEST, strlen($this->key_blob), $this->key_blob, strlen($message), $message, $this->flags);
        $packet = pack('Na*', strlen($packet), $packet);
        if (strlen($packet) != fputs($this->fsock, $packet)) {
            throw new \RuntimeException('Connection closed during signing');
        }

        $length = current(unpack('N', fread($this->fsock, 4)));
        $type = ord(fread($this->fsock, 1));
        if ($type != Agent::SSH_AGENT_SIGN_RESPONSE) {
            throw new \RuntimeException('Unable to retrieve signature');
        }

        $signature_blob = fread($this->fsock, $length - 1);
        $length = current(unpack('N', Strings::shift($signature_blob, 4)));
        if ($length != strlen($signature_blob)) {
            throw new \RuntimeException('Malformed signature blob');
        }
        $length = current(unpack('N', Strings::shift($signature_blob, 4)));
        if ($length > strlen($signature_blob) + 4) {
            throw new \RuntimeException('Malformed signature blob');
        }
        $type = Strings::shift($signature_blob, $length);
        Strings::shift($signature_blob, 4);

        return $signature_blob;
    }
}
