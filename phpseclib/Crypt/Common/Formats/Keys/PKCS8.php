<?php

/**
 * PKCS#8 Formatted Key Handler
 *
 * PHP version 5
 *
 * Used by PHP's openssl_public_encrypt() and openssl's rsautl (when -pubin is set)
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN ENCRYPTED PRIVATE KEY-----
 * -----BEGIN PRIVATE KEY-----
 * -----BEGIN PUBLIC KEY-----
 *
 * Analogous to ssh-keygen's pkcs8 format (as specified by -m). Although PKCS8
 * is specific to private keys it's basically creating a DER-encoded wrapper
 * for keys. This just extends that same concept to public keys (much like ssh-keygen)
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\Common\Formats\Keys;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Exception\InsufficientSetupException;
use phpseclib3\Exception\RuntimeException;
use phpseclib3\Exception\UnexpectedValueException;
use phpseclib3\Exception\UnsupportedAlgorithmException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Element;
use phpseclib3\File\ASN1\Types\BaseType;
use phpseclib3\File\ASN1\Types\ExplicitNull;
use phpseclib3\File\ASN1\Maps;

/**
 * PKCS#8 Formatted Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PKCS8 extends PKCS
{
    use \phpseclib3\Crypt\Common\Traits\ASN1AlgorithmIdentifier;

    /**
     * OIDs loaded
     *
     * @var bool
     */
    private static $oidsLoaded = false;

    /**
     * Binary key flag
     *
     * @var bool
     */
    private static $binary = false;

    /**
     * Initialize static variables
     */
    private static function initialize_static_variables(): void
    {
        if (!isset(static::$childOIDsLoaded)) {
            return;
        }

        if (!static::$childOIDsLoaded) {
            ASN1::loadOIDs(is_array(static::OID_NAME) ?
                array_combine(static::OID_NAME, static::OID_VALUE) :
                [static::OID_NAME => static::OID_VALUE]);
            static::$childOIDsLoaded = true;
        }
        if (!self::$oidsLoaded) {
            ASN1::loadOIDs('PKCS8');
            self::$oidsLoaded = true;
        }
    }

    /**
     * Break a public or private key down into its constituent components
     */
    protected static function load(string|array $key, #[SensitiveParameter] ?string $password = null): array
    {
        $isPublic = strpos($key, 'PUBLIC') !== false;
        $isPrivate = strpos($key, 'PRIVATE') !== false;

        $decoded = self::preParse($key);

        $meta = [];

        try {
            $decrypted = ASN1::map($decoded, Maps\EncryptedPrivateKeyInfo::MAP)->toArray();
        } catch (\Exception $e) {
            $decrypted = false;
        }

        if (is_array($decrypted)) {
            if (!isset($password)) {
                throw new RuntimeException('Key is encrypted but no password has been provided');
            }
            $cipher = self::getCryptoObjectFromAlgorithmIdentifier($decrypted['encryptionAlgorithm'], $password);
            $meta = $cipher->getMetaData('meta');
            $key = $cipher->decrypt((string) $decrypted['encryptedData']);
            try {
                $decoded = ASN1::decodeBER($key);
            } catch (\Exception $e) {
                throw new RuntimeException('Unable to decode BER', 0, $e);
            }
        }

        try {
            $private = ASN1::map($decoded, Maps\OneAsymmetricKey::MAP)->toArray();
        } catch (\Exception $e) {
            $private = false;
        }
        if (is_array($private)) {
            if ($isPublic) {
                throw new \UnexpectedValueException('Human readable string claims public key but DER encoded string claims private key');
            }

            if (isset($private['privateKeyAlgorithm']['parameters']) && !$private['privateKeyAlgorithm']['parameters'] instanceof ASN1\Element) {
                $private['privateKeyAlgorithm']['parameters'] = new ASN1\Element($private['privateKeyAlgorithm']['parameters']->getEncoded());
            }
            if (is_array(static::OID_NAME)) {
                if (!in_array($private['privateKeyAlgorithm']['algorithm'], static::OID_NAME)) {
                    throw new UnsupportedAlgorithmException($private['privateKeyAlgorithm']['algorithm'] . ' is not a supported key type');
                }
            } else {
                if ($private['privateKeyAlgorithm']['algorithm'] != static::OID_NAME) {
                    throw new UnsupportedAlgorithmException('Only ' . static::OID_NAME . ' keys are supported; this is a ' . $private['privateKeyAlgorithm']['algorithm'] . ' key');
                }
            }
            if (isset($private['publicKey'])) {
                $private['publicKey'] = (string) $private['publicKey'];
                if ($private['publicKey'][0] != "\0") {
                    throw new UnexpectedValueException('The first byte of the public key should be null - not ' . bin2hex($private['publicKey'][0]));
                }
                $private['publicKey'] = substr($private['publicKey'], 1);
            }
            return $private + $meta;
        }

        // EncryptedPrivateKeyInfo and PublicKeyInfo have largely identical "signatures". the only difference
        // is that the former has an octet string and the later has a bit string. the first byte of a bit
        // string represents the number of bits in the last byte that are to be ignored but, currently,
        // bit strings wanting a non-zero amount of bits trimmed are not supported
        try {
            $public = ASN1::map($decoded, Maps\PublicKeyInfo::MAP)->toArray();
        } catch (\Exception $e) {
            $public = false;
        }

        if (is_array($public)) {
            if ($isPrivate) {
                throw new \UnexpectedValueException('Human readable string claims private key but DER encoded string claims public key');
            }

            if ("$public[publicKey]"[0] != "\0") {
                throw new UnexpectedValueException('The first byte of the public key should be null - not ' . bin2hex($public['publicKey'][0]));
            }
            if (is_array(static::OID_NAME)) {
                if (!in_array($public['publicKeyAlgorithm']['algorithm'], static::OID_NAME)) {
                    throw new UnsupportedAlgorithmException($public['publicKeyAlgorithm']['algorithm'] . ' is not a supported key type');
                }
            } else {
                if ($public['publicKeyAlgorithm']['algorithm'] != static::OID_NAME) {
                    throw new UnsupportedAlgorithmException('Only ' . static::OID_NAME . ' keys are supported; this is a ' . $public['publicKeyAlgorithm']['algorithm'] . ' key');
                }
            }
            if (isset($public['publicKeyAlgorithm']['parameters']) && !$public['publicKeyAlgorithm']['parameters'] instanceof ASN1\Element) {
                $public['publicKeyAlgorithm']['parameters'] = new ASN1\Element($public['publicKeyAlgorithm']['parameters']->getEncoded());
            }
            $public['publicKey'] = substr((string) $public['publicKey'], 1);
            return $public;
        }

        throw new RuntimeException('Unable to parse using either OneAsymmetricKey or PublicKeyInfo ASN1 maps');
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

    /**
     * Wrap a private key appropriately
     */
    protected static function wrapPrivateKey(string $key, Element|BaseType $params = new ExplicitNull(), #[SensitiveParameter] ?string $password = null, ?string $oid = null, array $options = []): string
    {
        self::initialize_static_variables();

        $key = [
            'version' => 'v1',
            'privateKeyAlgorithm' => [
                'algorithm' => is_string(static::OID_NAME) ? static::OID_NAME : $oid,
             ],
            'privateKey' => $key,
        ];
        if ($oid != 'id-Ed25519' && $oid != 'id-Ed448') {
            $key['privateKeyAlgorithm']['parameters'] = $params;
        }
        //if (!empty($attr)) {
        //    $key['attributes'] = $attr;
        //}
        //if (!empty($publicKey)) {
        //    $key['version'] = 'v2';
        //    $key['publicKey'] = $publicKey;
        //}
        $key = ASN1::encodeDER($key, Maps\OneAsymmetricKey::MAP);
        if (isset($password)) {
            $crypto = self::getCryptoObjectFromParams($password, $options);
            $key = $crypto->encrypt($key);

            $key = [
                'encryptionAlgorithm' => $crypto->getMetaData('algorithmIdentifier'),
                'encryptedData' => $key,
            ];

            $key = ASN1::encodeDER($key, Maps\EncryptedPrivateKeyInfo::MAP);

            if ($options['binary'] ?? self::$binary) {
                return $key;
            }

            return "-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n" .
                   chunk_split(Strings::base64_encode($key), 64) .
                   "-----END ENCRYPTED PRIVATE KEY-----";
        }

        if ($options['binary'] ?? self::$binary) {
            return $key;
        }

        return "-----BEGIN PRIVATE KEY-----\r\n" .
               chunk_split(Strings::base64_encode($key), 64) .
               "-----END PRIVATE KEY-----";
    }

    /**
     * Wrap a public key appropriately
     */
    protected static function wrapPublicKey(string $key, Element|BaseType $params = new ExplicitNull(), ?string $oid = null, array $options = []): string
    {
        self::initialize_static_variables();

        $key = [
            'publicKeyAlgorithm' => [
                'algorithm' => is_string(static::OID_NAME) ? static::OID_NAME : $oid,
            ],
            'publicKey' => "\0" . $key,
        ];

        if ($oid != 'id-Ed25519' && $oid != 'id-Ed448') {
            $key['publicKeyAlgorithm']['parameters'] = $params;
        }

        $key = ASN1::encodeDER($key, Maps\PublicKeyInfo::MAP);

        if ($options['binary'] ?? self::$binary) {
            return $key;
        }

        return "-----BEGIN PUBLIC KEY-----\r\n" .
               chunk_split(Strings::base64_encode($key), 64) .
               "-----END PUBLIC KEY-----";
    }

    /**
     * Perform some preliminary parsing of the key
     */
    private static function preParse(string &$key): array
    {
        self::initialize_static_variables();

        if (self::$format != self::MODE_DER) {
            $decoded = ASN1::extractBER($key);
            if ($decoded !== false) {
                $key = $decoded;
            } elseif (self::$format == self::MODE_PEM) {
                throw new UnexpectedValueException('Expected base64-encoded PEM format but was unable to decode base64 text');
            }
        }

        try {
            $decoded = ASN1::decodeBER($key);
        } catch (\Exception $e) {
            throw new RuntimeException('Unable to decode BER', 0, $e);
        }

        return $decoded;
    }

    /**
     * Returns the encryption parameters used by the key
     */
    public static function extractEncryptionAlgorithm(string $key): array
    {
        $decoded = self::preParse($key);

        $r = ASN1::map($decoded, Maps\EncryptedPrivateKeyInfo::MAP)->toArray();

        if ($r['encryptionAlgorithm']['algorithm'] == 'id-PBES2') {
            $decoded = ASN1::decodeBER((string) $r['encryptionAlgorithm']['parameters']);
            $r['encryptionAlgorithm']['parameters'] = ASN1::map($decoded, Maps\PBES2params::MAP)->toArray();

            $kdf = &$r['encryptionAlgorithm']['parameters']['keyDerivationFunc'];
            switch ($kdf['algorithm']) {
                case 'id-PBKDF2':
                    $decoded = ASN1::decodeBER((string) $kdf['parameters']);
                    $kdf['parameters'] = ASN1::map($decoded, Maps\PBKDF2params::MAP)->toArray();
            }
        }

        return $r['encryptionAlgorithm'];
    }
}
