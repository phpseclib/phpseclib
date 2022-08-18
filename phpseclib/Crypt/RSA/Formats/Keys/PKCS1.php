<?php

/**
 * PKCS#1 Formatted RSA Key Handler
 *
 * PHP version 5
 *
 * Used by File/X509.php
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN RSA PRIVATE KEY-----
 * -----BEGIN RSA PUBLIC KEY-----
 *
 * Analogous to ssh-keygen's pem format (as specified by -m)
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\RSA\Formats\Keys;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\PKCS1 as Progenitor;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

/**
 * PKCS#1 Formatted RSA Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PKCS1 extends Progenitor
{
    /**
     * Break a public or private key down into its constituent components
     *
     * @param string|array $key
     * @param string|false $password
     */
    public static function load($key, ?string $password = null): array
    {
        if (!Strings::is_stringable($key)) {
            throw new \phpseclib3\Exception\UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        if (str_contains($key, 'PUBLIC')) {
            $components = ['isPublicKey' => true];
        } elseif (str_contains($key, 'PRIVATE')) {
            $components = ['isPublicKey' => false];
        } else {
            $components = [];
        }

        $key = parent::load($key, $password);

        $decoded = ASN1::decodeBER($key);
        if (!$decoded) {
            throw new \phpseclib3\Exception\RuntimeException('Unable to decode BER');
        }

        $key = ASN1::asn1map($decoded[0], Maps\RSAPrivateKey::MAP);
        if (is_array($key)) {
            $components += [
                'modulus' => $key['modulus'],
                'publicExponent' => $key['publicExponent'],
                'privateExponent' => $key['privateExponent'],
                'primes' => [1 => $key['prime1'], $key['prime2']],
                'exponents' => [1 => $key['exponent1'], $key['exponent2']],
                'coefficients' => [2 => $key['coefficient']],
            ];
            if ($key['version'] == 'multi') {
                foreach ($key['otherPrimeInfos'] as $primeInfo) {
                    $components['primes'][] = $primeInfo['prime'];
                    $components['exponents'][] = $primeInfo['exponent'];
                    $components['coefficients'][] = $primeInfo['coefficient'];
                }
            }
            if (!isset($components['isPublicKey'])) {
                $components['isPublicKey'] = false;
            }
            return $components;
        }

        $key = ASN1::asn1map($decoded[0], Maps\RSAPublicKey::MAP);

        if (!is_array($key)) {
            throw new \phpseclib3\Exception\RuntimeException('Unable to perform ASN1 mapping');
        }

        if (!isset($components['isPublicKey'])) {
            $components['isPublicKey'] = true;
        }

        return $components + $key;
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @param string|false $password
     * @param array $options optional
     */
    public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, ?string $password = null, array $options = []): string
    {
        $num_primes = count($primes);
        $key = [
            'version' => $num_primes == 2 ? 'two-prime' : 'multi',
            'modulus' => $n,
            'publicExponent' => $e,
            'privateExponent' => $d,
            'prime1' => $primes[1],
            'prime2' => $primes[2],
            'exponent1' => $exponents[1],
            'exponent2' => $exponents[2],
            'coefficient' => $coefficients[2],
        ];
        for ($i = 3; $i <= $num_primes; $i++) {
            $key['otherPrimeInfos'][] = [
                'prime' => $primes[$i],
                'exponent' => $exponents[$i],
                'coefficient' => $coefficients[$i],
            ];
        }

        $key = ASN1::encodeDER($key, Maps\RSAPrivateKey::MAP);

        return self::wrapPrivateKey($key, 'RSA', $password, $options);
    }

    /**
     * Convert a public key to the appropriate format
     */
    public static function savePublicKey(BigInteger $n, BigInteger $e): string
    {
        $key = [
            'modulus' => $n,
            'publicExponent' => $e,
        ];

        $key = ASN1::encodeDER($key, Maps\RSAPublicKey::MAP);

        return self::wrapPublicKey($key, 'RSA');
    }
}
