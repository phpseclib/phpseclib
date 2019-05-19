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
use phpseclib\Crypt\Common\PrivateKey;


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
class Identity implements PrivateKey
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
        return $this->key;
    }

    /**
     * Sets the hash
     *
     * @param string $hash
     * @access public
     */
    public function withHash($hash)
    {
        $new = clone $this;
        $new->flags = 0;
        switch ($hash) {
            case 'sha1':
                break;
            case 'sha256':
                $new->flags = self::SSH_AGENT_RSA2_256;
                break;
            case 'sha512':
                $new->flags = self::SSH_AGENT_RSA2_512;
                break;
            default:
                throw new UnsupportedAlgorithmException('The only supported hashes for RSA are sha1, sha256 and sha512');
        }
        return $new;
    }

    /**
     * Sets the padding
     *
     * Only PKCS1 padding is supported
     *
     * @param string $padding
     * @access public
     */
    public function withPadding($padding = RSA::SIGNATURE_PKCS1)
    {
        if ($padding != RSA::SIGNATURE_PKCS1 && $padding != RSA::SIGNATURE_RELAXED_PKCS1) {
            throw new UnsupportedAlgorithmException('ssh-agent can only create PKCS1 signatures');
        }
        return $this;
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
    public function sign($message)
    {
        // the last parameter (currently 0) is for flags and ssh-agent only defines one flag (for ssh-dss): SSH_AGENT_OLD_SIGNATURE
        $packet = Strings::packSSH2(
            'CssN',
            Agent::SSH_AGENTC_SIGN_REQUEST,
            $this->key_blob,
            $message,
            $this->flags
        );
        $packet = Strings::packSSH2('s', $packet);
        if (strlen($packet) != fputs($this->fsock, $packet)) {
            throw new \RuntimeException('Connection closed during signing');
        }

        $length = current(unpack('N', fread($this->fsock, 4)));
        $packet = fread($this->fsock, $length);

        list($type, $signature_blob) = Strings::unpackSSH2('Cs', $packet);
        if ($type != Agent::SSH_AGENT_SIGN_RESPONSE) {
            throw new \RuntimeException('Unable to retrieve signature');
        }

        list($type, $signature_blob) = Strings::unpackSSH2('ss', $signature_blob);

        return $signature_blob;
    }

    /**
     * Returns the private key
     *
     * @param string $type
     * @return string
     */
    public function toString($type)
    {
        throw new \RuntimeException('ssh-agent does not provide a mechanism to get the private key');
    }

    /**
     * Sets the password
     *
     * @access public
     * @param string|boolean $password
     */
    public function withPassword($password = false)
    {
        throw new \RuntimeException('ssh-agent does not provide a mechanism to get the private key');
    }
}
