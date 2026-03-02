<?php
/**
 * Pure-PHP CMS / KeyAgreeRecipient / EncryptedKey Parser
 *
 * PHP version 8
 *
 * Encode and decode CMS / EnvelopedData / KeyAgreeRecipient / EncryptedKey files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\CMS\EnvelopedData\KeyAgreeRecipient;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\CMS\EncryptedData;
use phpseclib4\File\CMS\EnvelopedData\DerivableKey;
use phpseclib4\File\CMS\EnvelopedData\KeyAgreeRecipient;
use phpseclib4\File\CMS\EnvelopedData\SearchableKey;
use phpseclib4\File\X509;

class EncryptedKey implements DerivableKey, SearchableKey, \ArrayAccess, \Countable, \Iterator
{
    use \phpseclib4\File\Common\Traits\KeyDerivation;

    public Constructed|array $encryptedKey;
    public EncryptedData $cms;
    public KeyAgreeRecipient $recipient;
    private EC\PrivateKey $kek;
    public ?Constructed $parent;
    public int $depth = 0;
    public int|string $key;

    public function __construct(Constructed|array $key)
    {
        $this->encryptedKey = $key;
    }

    public static function load(string|array|Constructed $encoded): static
    {
        $r = new \ReflectionClass(__CLASS__);
        $cms = $r->newInstanceWithoutConstructor();
        $temp->encryptedKey = is_string($encoded) ? static::loadString($encoded) : $encoded;
        return $temp;
    }

    protected static function loadString(string $encoded): Constructed
    {
        //ASN1::disableCacheInvalidation();
        $decoded = ASN1::decodeBER($encoded);
        $temp = ASN1::map($decoded, Maps\RecipientEncryptedKey::MAP);
        //ASN1::enableCacheInvalidation();
        return $temp;
    }

    public function withKey(#[\SensitiveParameter] EC\PrivateKey $key): self
    {
        $private = &$key;

        $originatorKey = $this->recipient['originator']['originatorKey'];
        // we do this because https://datatracker.ietf.org/doc/html/rfc5753#section-3.1.1 says this:
        /*
          The parameters associated with id-ecPublicKey MUST be absent, ECParameters, or NULL.  The
          parameters associated with id-ecPublicKey SHOULD be absent or ECParameters, and NULL is
          allowed to support legacy implementations.  The previous version of this document required
          NULL to be present.
        */
        // PublicKeyLoader::load() won't work if parameters isn't present. like it won't know what curve it is and thus
        // won't be able to load it
        $encoded = $private->getPublicKey()->toString('PKCS8', ['binary' => true]);
        $decoded = ASN1::decodeBER($encoded);
        $mapped = ASN1::map($decoded, Maps\SubjectPublicKeyInfo::MAP);
        $originatorKey['algorithm']['parameters'] = $mapped['algorithm']['parameters'];
        $encoded = ASN1::encodeDER($originatorKey, Maps\OriginatorPublicKey::MAP);
        $public = PublicKeyLoader::load($encoded);

        $secret = \phpseclib4\Crypt\DH::computeSecret($private, $public);

        $dhAlgo = (string) $this->recipient['keyEncryptionAlgorithm']['algorithm'];
        // in standard DH you multiply the private and public key together to get the secret
        // in cofactor DH you multiply the above result by the cofactor as well
        // prime curves always have a cofactor of 1 so standard and cofactor DH yield the same results
        // binary curves have a cofactor of 2 or 4 so standard and cofactor DH yield different results
        if (str_starts_with($dhAlgo, 'dhSinglePass-cofactorDH-') && $private->isBinaryCurve()) {
            throw new UnsupportedAlgorithmException('Cofactor DH on binary curves is not supported');
        }
        if (str_starts_with($dhAlgo, 'mqvSinglePass-')) {
            throw new UnsupportedAlgorithmException('MQV DH is not supported');
        }
        $cekAlgo = (string) $this->recipient['keyEncryptionAlgorithm']['parameters']['algorithm'];
        $length = match ($cekAlgo) {
            'id-aes256-wrap' => 32,
            'id-aes192-wrap' => 24,
            'id-aes128-wrap' => 16,
            'id-alg-CMS3DESwrap' => 24,
            default => null
        };
        if (!isset($length)) {
            throw new UnsupportedAlgorithmException($this->recipient['keyEncryptionAlgorithm']['parameters']['algorithm'] . ' is not a supported algorithm');
        }
        $sharedInfo = [
            'keyInfo' => new ASN1\Element($this->recipient['keyEncryptionAlgorithm']['parameters']->getEncoded()),
            'suppPubInfo' => pack('N', $length << 3)
        ];
        // this can't be set via OpenSSL CLI
        if (isset($this->recipient['ukm'])) {
            $sharedInfo['entityUInfo'] = $this->recipient['ukm'];
        }
        $sharedInfo = ASN1::encodeDER($sharedInfo, Maps\ECCCMSSharedInfo::MAP);

        if (!preg_match('#DH-(sha\d+)kdf-scheme$#', (string) $this->recipient['keyEncryptionAlgorithm']['algorithm'], $matches)) {
            throw new UnsupportedAlgorithmException($this->recipient['keyEncryptionAlgorithm']['algorithm'] . ' is not a supported algorithm');
        }
        $hash = new \phpseclib4\Crypt\Hash($matches[1]);
        $kek = EncryptedData::ANSIX963KDF($secret, $length, $sharedInfo, $hash);

        $encryptedKey = (string) $this->encryptedKey['encryptedKey'];
        if ($cekAlgo == 'id-alg-CMS3DESwrap') {
            $cek = self::unwrapDES($kek, $encryptedKey);
        } else {
            $iv = "\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6";
            $cek = self::unwrapAES($kek, $iv, $encryptedKey);
        }

        //if (!$this->cms instanceof Constructed) {
        $this->cms->cek = $cek;
        //}

        return $this;
    }

    public function matchesX509(X509 $x509): bool
    {
        return $x509->isIssuerOf($this->encryptedKey['rid'], ['keyAgreement']);
    }

    public function compile(): void
    {
        if (!$this->encryptedKey instanceof Constructed) {
            $temp = self::load("$this");
            $this->encryptedKey = $temp->encryptedKey;
            return;
        }
        if ($this->encryptedKey->hasEncoded()) {
            return;
        }
        $oldParent = $this->encryptedKey->parent;
        $temp = self::load("$this");
        $this->encryptedKey = $temp->encryptedKey;
        $this->encryptedKey->parent = $oldParent;
    }

    public function getEncoded(): string
    {
        $this->compile();
        return $this->encryptedKey->getEncoded();
    }

    public function &offsetGet(mixed $offset): mixed
    {
        $this->compile();
        return $this->encryptedKey[$offset];
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->encryptedKey[$offset]);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->encryptedKey[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->encryptedKey[$offset]);
    }

    public function count(): int
    {
        return is_array($this->encryptedKey) ? count($this->encryptedKey) : $this->encryptedKey->count();
    }

    public function rewind(): void
    {
        $this->compile();
        $this->encryptedKey->rewind();
    }

    public function current(): mixed
    {
        $this->compile();
        return $this->encryptedKey->current();
    }

    public function key(): mixed
    {
        $this->compile();
        return $this->encryptedKey->key();
    }

    public function next(): void
    {
        $this->compile();
        $this->encryptedKey->next();
    }

    public function valid(): bool
    {
        $this->compile();
        return $this->encryptedKey->valid();
    }

    public function keys(): array
    {
        return $this->encryptedKey instanceof Constructed ? $this->encryptedKey->keys() : array_keys($this->encryptedKey);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function __debugInfo(): array
    {
        $this->compile();
        return $this->encryptedKey->__debugInfo();
    }

    public function toArray(bool $convertPrimitives = false): array
    {
        $this->compile();
        return $this->encryptedKey instanceof Constructed ? $this->encryptedKey->toArray($convertPrimitives) : $this->encryptedKey;
    }
}