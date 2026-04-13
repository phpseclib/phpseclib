<?php

/**
 * Pure-PHP ssh-agent client.
 *
 * {@internal See http://api.libssh.org/rfc/PROTOCOL.agent}
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\System\SSH\Agent;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\Common\PrivateKey;
use phpseclib4\Crypt\Common\PublicKey;
use phpseclib4\Crypt\DSA;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\RSA;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\File\Common\Signable;
use phpseclib4\File\CSR;
use phpseclib4\System\SSH\Agent;
use phpseclib4\System\SSH\Common\Traits\ReadBytes;

/**
 * Pure-PHP ssh-agent client identity object
 *
 * Instantiation should only be performed by \phpseclib4\System\SSH\Agent class.
 * This could be thought of as implementing an interface that phpseclib4\Crypt\RSA
 * implements. ie. maybe a Net_SSH_Auth_PublicKey interface or something.
 * The methods in this interface would be getPublicKey and sign since those are the
 * methods phpseclib looks for to perform public key authentication.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @internal
 */
class Identity implements PrivateKey
{
    use ReadBytes;

    // Signature Flags
    // See https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-5.3
    public const SSH_AGENT_RSA2_256 = 2;
    public const SSH_AGENT_RSA2_512 = 4;

    /**
     * Key Object
     *
     * @see self::getPublicKey()
     */
    private PublicKey $key;

    /**
     * Key Blob
     *
     * @see self::sign()
     */
    private string $key_blob;

    /**
     * Socket Resource
     *
     * @var resource
     * @see self::sign()
     */
    private $fsock;

    /**
     * Signature flags
     *
     * @see self::sign()
     * @see self::setHash()
     */
    private int $flags = 0;

    /**
     * Comment
     */
    private ?string $comment;

    /**
     * Curve Aliases
     */
    private static array $curveAliases = [
        'secp256r1' => 'nistp256',
        'secp384r1' => 'nistp384',
        'secp521r1' => 'nistp521',
        'Ed25519' => 'Ed25519',
    ];

    /**
     * Default Constructor.
     *
     * @param resource $fsock
     */
    public function __construct($fsock)
    {
        $this->fsock = $fsock;
    }

    /**
     * Set Public Key
     *
     * Called by \phpseclib4\System\SSH\Agent::requestIdentities()
     */
    public function withPublicKey(PublicKey $key): Identity
    {
        if ($key instanceof EC) {
            if (is_array($key->getCurve()) || !isset(self::$curveAliases[$key->getCurve()])) {
                throw new UnsupportedAlgorithmException('The only supported curves are nistp256, nistp384, nistp512 and Ed25519');
            }
        }

        $new = clone $this;
        $new->key = $key;
        return $new;
    }

    /**
     * Set Public Key
     *
     * Called by \phpseclib4\System\SSH\Agent::requestIdentities(). The key blob could be extracted from $this->key
     * but this saves a small amount of computation.
     */
    public function withPublicKeyBlob(string $key_blob): Identity
    {
        $new = clone $this;
        $new->key_blob = $key_blob;
        return $new;
    }

    /**
     * Get Public Key
     *
     * Wrapper for $this->key->getPublicKey()
     */
    public function getPublicKey(): PublicKey
    {
        return $this->key;
    }

    /**
     * Sets the hash
     */
    public function withHash(string $hash): Identity
    {
        $new = clone $this;

        $hash = strtolower($hash);

        if ($this->key instanceof RSA) {
            $new->flags = match ($hash) {
                'sha1' => 0,
                'sha256' => self::SSH_AGENT_RSA2_256,
                'sha512' => self::SSH_AGENT_RSA2_512,
                default => throw new UnsupportedAlgorithmException('The only supported hashes for RSA are sha1, sha256 and sha512')
            };
        }
        if ($this->key instanceof EC) {
            $expectedHash = match ($this->key->getCurve()) {
                'secp256r1' => 'sha256',
                'secp384r1' => 'sha384',
                default => 'sha512' // eg. secp512r1 or Ed25519
            };
            if ($hash != $expectedHash) {
                throw new UnsupportedAlgorithmException('The only supported hash for ' . self::$curveAliases[$this->key->getCurve()] . ' is ' . $expectedHash);
            }
        }
        if ($this->key instanceof DSA) {
            if ($hash != 'sha1') {
                throw new UnsupportedAlgorithmException('The only supported hash for DSA is sha1');
            }
        }
        return $new;
    }

    /**
     * Sets the padding
     *
     * Only PKCS1 padding is supported
     */
    public function withPadding(int $padding): Identity
    {
        if (!$this->key instanceof RSA) {
            throw new UnsupportedAlgorithmException('Only RSA keys support padding');
        }
        if ($padding != RSA::SIGNATURE_PKCS1) {
            throw new UnsupportedAlgorithmException('ssh-agent can only create PKCS1 signatures');
        }
        return $this;
    }

    /**
     * Determines the signature padding mode
     *
     * Valid values are: ASN1, SSH2, Raw
     */
    public function withSignatureFormat(string $format): Identity
    {
        if ($this->key instanceof RSA) {
            throw new UnsupportedAlgorithmException('Only DSA and EC keys support signature format setting');
        }
        if ($format != 'SSH2') {
            throw new UnsupportedAlgorithmException('Only SSH2-formatted signatures are currently supported');
        }

        return $this;
    }

    /**
     * Returns the curve
     *
     * Returns a string if it's a named curve, an array if not
     */
    public function getCurve(): string|array
    {
        if (!$this->key instanceof EC) {
            throw new UnsupportedAlgorithmException('Only EC keys have curves');
        }

        return $this->key->getCurve();
    }

    /**
     * Create a signature
     *
     * See "2.6.2 Protocol 2 private key signature request"
     *
     * @throws RuntimeException on connection errors
     * @throws UnsupportedAlgorithmException if the algorithm is unsupported
     */
    public function sign(string|Signable $source): string
    {
        if ($source instanceof Signable) {
            if ($source instanceof CSR && !$source->hasPublicKey()) {
                $source->setPublicKey($this->getPublicKey());
            }
            $source->identifySignatureAlgorithm($this->getPublicKey());
            $message = $source->getSignableSection();
        } else {
            $message = $source;
        }

        // the last parameter (currently 0) is for flags and ssh-agent only defines one flag (for ssh-dss): SSH_AGENT_OLD_SIGNATURE
        $packet = Strings::packSSH2(
            'CssN',
            Agent::SSH_AGENTC_SIGN_REQUEST,
            $this->key_blob,
            $message,
            $this->flags
        );
        $packet = Strings::packSSH2('s', $packet);
        if (strlen($packet) != fwrite($this->fsock, $packet)) {
            throw new RuntimeException('Connection closed during signing');
        }

        $length = current(unpack('N', $this->readBytes(4)));
        $packet = $this->readBytes($length);

        [$type, $signature_blob] = Strings::unpackSSH2('Cs', $packet);
        if ($type != Agent::SSH_AGENT_SIGN_RESPONSE) {
            throw new RuntimeException('Unable to retrieve signature');
        }

        if ($this->key instanceof RSA) {
            [$type, $signature_blob] = Strings::unpackSSH2('ss', $signature_blob);
        }

        if ($source instanceof Signable) {
            $source->setSignature($signature_blob);
        }

        return $signature_blob;
    }

    /**
     * Returns the private key
     *
     * @param array $options optional
     */
    public function toString(string $type, array $options = []): string
    {
        throw new RuntimeException('ssh-agent does not provide a mechanism to get the private key');
    }

    /**
     * Sets the password
     *
     * @return never
     */
    public function withPassword(#[SensitiveParameter] ?string $password = null): PrivateKey
    {
        throw new RuntimeException('ssh-agent does not provide a mechanism to get the private key');
    }

    /**
     * Sets the comment
     */
    public function withComment($comment = null): PrivateKey
    {
        $new = clone $this;
        $new->comment = $comment;
        return $new;
    }

    /**
     * Returns the comment
     */
    public function getComment(): ?string
    {
        return $this->comment;
    }
}
