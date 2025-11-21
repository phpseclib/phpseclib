<?php

/**
 * PKCS#8 Formatted RSA-PSS Key Handler
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
 * Analogous to "openssl genpkey -algorithm rsa-pss".
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\RSA\Formats\Keys;

use phpseclib3\Crypt\Common\Formats\Keys\PKCS8 as Progenitor;
use phpseclib3\Exception\UnexpectedValueException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Element;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

/**
 * PKCS#8 Formatted RSA-PSS Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PSS extends Progenitor
{
    /**
     * OID Name
     *
     * @var string
     */
    public const OID_NAME = 'id-RSASSA-PSS';

    /**
     * OID Value
     *
     * @var string
     */
    public const OID_VALUE = '1.2.840.113549.1.1.10';

    /**
     * OIDs loaded
     *
     * @var bool
     */
    private static $oidsLoaded = false;

    /**
     * Child OIDs loaded
     *
     * @var bool
     */
    protected static $childOIDsLoaded = false;

    /**
     * Initialize static variables
     */
    private static function initialize_static_variables(): void
    {
        if (!self::$oidsLoaded) {
            ASN1::loadOIDs('Hashes');
            self::$oidsLoaded = true;
        }
    }

    /**
     * Break a public or private key down into its constituent components
     *
     * @param string|array $key
     */
    public static function load(string|array $key, ?string $password = null): array
    {
        self::initialize_static_variables();

        if (!is_string($key)) {
            throw new UnexpectedValueException('Key should be a string - not an array');
        }

        if (str_contains($key, 'PUBLIC')) {
            $components = ['isPublicKey' => true];
        } elseif (str_contains($key, 'PRIVATE')) {
            $components = ['isPublicKey' => false];
        } else {
            $components = [];
        }

        $key = parent::load($key, $password);

        if (isset($key['privateKey'])) {
            if (!isset($components['isPublicKey'])) {
                $components['isPublicKey'] = false;
            }
            $type = 'private';
        } else {
            if (!isset($components['isPublicKey'])) {
                $components['isPublicKey'] = true;
            }
            $type = 'public';
        }

        $result = $components + PKCS1::load((string) $key[$type . 'Key']);

        if (isset($key[$type . 'KeyAlgorithm']['parameters'])) {
            try {
                $decoded = ASN1::decodeBER((string) $key[$type . 'KeyAlgorithm']['parameters']);
                $params = ASN1::map($decoded, Maps\RSASSA_PSS_params::MAP);
            } catch (\Exception $e) {
                throw new UnexpectedValueException('Unable to decode parameters', 0, $e);
            }
        } else {
            $params = [];
        }

        if (isset($params['maskGenAlgorithm']['parameters'])) {
            try {
                $decoded = ASN1::decodeBER((string) $params['maskGenAlgorithm']['parameters']);
                $params['maskGenAlgorithm']['parameters'] = ASN1::map($decoded, Maps\HashAlgorithm::MAP);
            } catch (\Exception $e) {
                throw new UnexpectedValueException('Unable to decode parameters', 0, $e);
            }
        } else {
            $params['maskGenAlgorithm'] = [
                'algorithm' => 'id-mgf1',
                'parameters' => ['algorithm' => 'id-sha1'],
            ];
        }

        if (!isset($params['hashAlgorithm']['algorithm'])) {
            $params['hashAlgorithm']['algorithm'] = 'id-sha1';
        }

        $result['hash'] = str_replace('id-', '', (string) $params['hashAlgorithm']['algorithm']);
        $result['MGFHash'] = str_replace('id-', '', (string) $params['maskGenAlgorithm']['parameters']['algorithm']);
        if (isset($params['saltLength'])) {
            if (is_int($params['saltLength'])) {
                $result['saltLength'] = $params['saltLength'];
            } else {
                $result['saltLength'] = (int) $params['saltLength']->toString();
            }
        }

        if (isset($key['meta'])) {
            $result['meta'] = $key['meta'];
        }

        return $result;
    }

    /**
     * Convert a private key to the appropriate format.
     */
    public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, ?string $password = null, array $options = []): string
    {
        self::initialize_static_variables();

        $key = PKCS1::savePrivateKey($n, $e, $d, $primes, $exponents, $coefficients);
        $key = ASN1::extractBER($key);
        $params = self::savePSSParams($options);
        return self::wrapPrivateKey(
            key: $key,
            params: $params,
            password: $password,
            options: $options
        );
    }

    /**
     * Convert a public key to the appropriate format
     */
    public static function savePublicKey(BigInteger $n, BigInteger $e, array $options = []): string
    {
        self::initialize_static_variables();

        $key = PKCS1::savePublicKey($n, $e);
        $key = ASN1::extractBER($key);
        $params = self::savePSSParams($options);
        return self::wrapPublicKey(
            key: $key,
            params: $params
        );
    }

    /**
     * Encodes PSS parameters
     */
    public static function savePSSParams(array $options): Element
    {
        /*
         The trailerField field is an integer.  It provides
         compatibility with IEEE Std 1363a-2004 [P1363A].  The value
         MUST be 1, which represents the trailer field with hexadecimal
         value 0xBC.  Other trailer fields, including the trailer field
         composed of HashID concatenated with 0xCC that is specified in
         IEEE Std 1363a, are not supported.  Implementations that
         perform signature generation MUST omit the trailerField field,
         indicating that the default trailer field value was used.
         Implementations that perform signature validation MUST
         recognize both a present trailerField field with value 1 and an
         absent trailerField field.

         source: https://tools.ietf.org/html/rfc4055#page-9
        */
        $params = [
            'trailerField' => new BigInteger(1),
        ];
        if (isset($options['hash'])) {
            $params['hashAlgorithm']['algorithm'] = 'id-' . $options['hash'];
        }
        if (isset($options['MGFHash'])) {
            $temp = ['algorithm' => 'id-' . $options['MGFHash']];
            $temp = ASN1::encodeDER($temp, Maps\HashAlgorithm::MAP);
            $params['maskGenAlgorithm'] = [
                'algorithm' => 'id-mgf1',
                'parameters' => new ASN1\Element($temp),
            ];
        }
        if (isset($options['saltLength'])) {
            $params['saltLength'] = new BigInteger($options['saltLength']);
        }

        return new ASN1\Element(ASN1::encodeDER($params, Maps\RSASSA_PSS_params::MAP));
    }
}
