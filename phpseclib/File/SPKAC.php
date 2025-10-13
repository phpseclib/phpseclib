<?php

/**
 * Pure-PHP SPKAC Parser
 *
 * PHP version 8
 *
 * Encode and decode SPKACs.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\File;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Exception\NoKeyLoadedException;
use phpseclib3\Exception\RuntimeException;
use phpseclib3\File\ASN1\Constructed;
use phpseclib3\File\ASN1\Element;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\File\ASN1\Types\BitString;
use phpseclib3\File\Common\Signable;

/**
 * Pure-PHP SPKAC Parser
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class SPKAC implements \ArrayAccess, \Countable, \Iterator, Signable
{
    use \phpseclib3\File\Common\Traits\ASN1Signature;

    private Constructed|array $spkac;

    /**
     * Binary key flag
     */
    private static bool $binary = false;

    public function __construct(?PublicKey $public = null)
    {
        ASN1::loadOIDs('X509');

        $this->spkac = [
            'publicKeyAndChallenge' => [
                'spki' => [
                    'algorithm' => ['algorithm' => '0.0'],
                    'subjectPublicKey' => "\0",
                ],
                // quoting <https://developer.mozilla.org/en-US/docs/Web/HTML/Element/keygen>,
                // "A challenge string that is submitted along with the public key. Defaults to an empty string if not specified."
                // both Firefox and OpenSSL ("openssl spkac -key private.key") behave this way
                // we could alternatively do this instead if we ignored the specs:
                // Random::string(8) & str_repeat("\x7F", 8)
                'challenge' => '',
            ],
            'signatureAlgorithm' => [
                'algorithm' => '0.0',
            ],
            'signature' => "\0",
        ];

        if ($public instanceof PublicKey) {
            $this->setPublicKey($public);
        }
    }

    /**
     * Enable binary output (DER)
     */
    public static function enableBinaryOutput(): void
    {
        self::$binary = true;
    }

    /**
     * Disable binary output (ie. enable PEM)
     */
    public static function disableBinaryOutput(): void
    {
        self::$binary = false;
    }

    public function hasPublicKey(): bool
    {
        return $this->spkac['publicKeyAndChallenge']['spki'] instanceof PublicKey;
    }

    public function setPublicKey(PublicKey $publicKey): void
    {
        $this->spkac['publicKeyAndChallenge']['spki'] = $publicKey;
    }

    public function removePublicKey(): void
    {
        $this->spkac['publicKeyAndChallenge']['spki'] = [
            'algorithm' => ['algorithm' => '0.0'],
            'subjectPublicKey' => "\0",
        ];
    }

    public static function load(string|array|Constructed $spkac, int $mode = ASN1::FORMAT_AUTO_DETECT): SPKAC
    {
        $new = new self();
        $new->spkac = is_string($spkac) ? self::loadString($spkac, $mode) : $spkac;
        return $new;
    }

    private static function loadString(string $spkac, int $mode): ?Constructed
    {
        if ($mode != ASN1::FORMAT_DER) {
            $newspkac = ASN1::extractBER($spkac);
            if ($mode == ASN1::FORMAT_PEM && $spkac == $newspkac) {
                return null;
            }
            $spkac = $newspkac;
        }

        // see http://www.w3.org/html/wg/drafts/html/master/forms.html#signedpublickeyandchallenge

        // OpenSSL produces SPKAC's that are preceded by the string SPKAC=
        $temp = preg_replace('#(?:SPKAC=)|[ \r\n\\\]#', '', $spkac);
        $temp = preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $temp) ? Strings::base64_decode($temp) : false;
        if ($temp != false) {
            $spkac = $temp;
        }

        $decoded = ASN1::decodeBER($spkac);

        $rules = [];
        $rules['publicKeyAndChallenge']['spki'] = function(Constructed &$spkac) {
            try {
                $spkac = PublicKeyLoader::load($spkac->getEncoded());
            } catch (NoKeyLoadedException $e) {
            }
        };

        return ASN1::map($decoded, Maps\SignedPublicKeyAndChallenge::MAP, $rules);
    }

    /**
     * Set challenge
     */
    public function setChallenge(string $challenge): void
    {
        $this->spkac['publicKeyAndChallenge']['challenge'] = $challenge & str_repeat("\x7F", strlen($challenge));
    }

    public function getChallenge(): string
    {
        $this->compile();
        return $this->spkac['publicKeyAndChallenge']['challenge']->value;
    }

    public function __toString(): string
    {
        $publicKey = $this->spkac['publicKeyAndChallenge']['spki'] ;
        if ($publicKey instanceof PublicKey) {
            $origKey = $publicKey;
            $this->spkac['publicKeyAndChallenge']['spki']  = new Element($publicKey->toString('PKCS8', ['binary' => true]));
        }

        $spkac = ASN1::encodeDER($this->spkac, Maps\SignedPublicKeyAndChallenge::MAP);
        if (isset($origKey)) {
            $this->spkac['publicKeyAndChallenge']['spki'] = $origKey;
        }

        return self::$binary ? $spkac : 'SPKAC=' . Strings::base64_encode($spkac);
    }

    public function getSignableSection(): string
    {
        $this->compile();
        return $this->spkac['publicKeyAndChallenge']->getEncoded();
    }

    public function setSignature(string $signature): void
    {
        $this->spkac['signature'] = new BitString("\0$signature");
    }

    public function setSignatureAlgorithm(array $algorithm): void
    {
        $this->spkac['publicKeyAndChallenge']['signature'] = $algorithm;
        $this->spkac['signatureAlgorithm'] = $algorithm;
    }

    /**
     * Identify signature algorithm from private key
     *
     * @throws UnsupportedAlgorithmException if the algorithm is unsupported
     */
    public static function identifySignatureAlgorithm(PrivateKey $key): array
    {
        return self::identifySignatureAlgorithmHelper($key);
    }

    private function compile(): void
    {
        if (!$this->spkac instanceof Constructed) {
            $temp = self::load("$this");
            $this->spkac = $temp->spkac;
        }
        if ($this->spkac->hasEncoded()) {
            return;
        }
        $temp = self::load("$this");
        $this->spkac = $temp->spkac;
    }

    public function __debugInfo(): array
    {
        $this->compile();
        return $this->spkac->__debugInfo();
    }

    public function getPublicKey(): PublicKey
    {
        if (!$this->spkac['publicKeyAndChallenge']['spki'] instanceof PublicKey) {
            throw new RuntimeException('Unable to decode spki');
        }

        $publicKey = $this->spkac['publicKeyAndChallenge']['spki'];
        if ($publicKey instanceof RSA && $publicKey->getLoadedFormat() == 'PKCS8') {
            return $publicKey->withPadding(RSA::SIGNATURE_PKCS1);
        }
        return $publicKey;
    }

    public function toArray(bool $convertPrimitives = false): array
    {
        return $this->spkac instanceof Constructed ? $this->spkac->toArray($convertPrimitives) : $this->spkac;
    }

    /**
     * Validate a signature
     *
     * Returns true if the signature is verified, false if it is not correct or on error
     *
     * The behavior of this function is inspired by {@link http://php.net/openssl-verify openssl_verify}.
     */
    public function validateSignature(): bool
    {
        return self::validateSignatureHelper(
            $this->getPublicKey(),
            $this->spkac['signatureAlgorithm']['algorithm'],
            $this->spkac['signature'],
            $this->spkac['publicKeyAndChallenge']->getEncoded()
        );
    }

    public function count(): int
    {
        return is_array($this->spkac) ? count($this->spkac) : $this->spkac->count();
    }

    public function rewind(): void
    {
        $this->compile();
        $this->spkac->rewind();
    }

    public function current(): mixed
    {
        $this->compile();
        return $this->spkac->current();
    }

    public function key(): mixed
    {
        $this->compile();
        return $this->spkac->key();
    }

    public function next(): void
    {
        $this->compile();
        $this->spkac->next();
    }

    public function valid(): bool
    {
        $this->compile();
        return $this->spkac->valid();
    }

    public function &offsetGet(mixed $offset): mixed
    {
        $this->compile();
        return $this->spkac[$offset];
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->spkac[$offset]);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->spkac[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->spkac[$offset]);
    }
}