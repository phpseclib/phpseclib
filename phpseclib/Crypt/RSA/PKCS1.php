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
 * @category  Crypt
 * @package   RSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\RSA;

use phpseclib\Math\BigInteger;
use phpseclib\Crypt\Common\PKCS1 as Progenitor;
use phpseclib\File\ASN1;

// version must be multi if otherPrimeInfos present
define(__NAMESPACE__ . '\Version', [
    'type'    => ASN1::TYPE_INTEGER,
    'mapping' => ['two-prime', 'multi']
]);

define(__NAMESPACE__ . '\OtherPrimeInfo', [
    'type' => ASN1::TYPE_SEQUENCE,
    'children' => [
        'prime' =>       ['type' => ASN1::TYPE_INTEGER], // ri
        'exponent' =>    ['type' => ASN1::TYPE_INTEGER], // di
        'coefficient' => ['type' => ASN1::TYPE_INTEGER]  // ti
    ]
]);

define(__NAMESPACE__ . '\OtherPrimeInfos', [
    'type' => ASN1::TYPE_SEQUENCE,
    'min' => 1,
    'max' => -1,
    'children' => OtherPrimeInfo
]);

define(__NAMESPACE__ . '\RSAPrivateKey', [
    'type' => ASN1::TYPE_SEQUENCE,
    'children' => [
        'version' =>         Version,
        'modulus' =>         ['type' => ASN1::TYPE_INTEGER], // n
        'publicExponent' =>  ['type' => ASN1::TYPE_INTEGER], // e
        'privateExponent' => ['type' => ASN1::TYPE_INTEGER], // d
        'prime1' =>          ['type' => ASN1::TYPE_INTEGER], // p
        'prime2' =>          ['type' => ASN1::TYPE_INTEGER], // q
        'exponent1' =>       ['type' => ASN1::TYPE_INTEGER], // d mod (p-1)
        'exponent2' =>       ['type' => ASN1::TYPE_INTEGER], // d mod (q-1)
        'coefficient' =>     ['type' => ASN1::TYPE_INTEGER], // (inverse of q) mod p
        'otherPrimeInfos' => OtherPrimeInfos + ['optional' => true]
    ]
]);

define(__NAMESPACE__ . '\RSAPublicKey', [
    'type' => ASN1::TYPE_SEQUENCE,
    'children' => [
        'modulus' =>         ['type' => ASN1::TYPE_INTEGER],
        'publicExponent' =>  ['type' => ASN1::TYPE_INTEGER]
    ]
]);

/**
 * PKCS#1 Formatted RSA Key Handler
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class PKCS1 extends Progenitor
{
    /**
     * Break a public or private key down into its constituent components
     *
     * @access public
     * @param string $key
     * @param string $password optional
     * @return array
     */
    static function load($key, $password = '')
    {
        if (!is_string($key)) {
            return false;
        }

        $components = ['isPublicKey' => strpos($key, 'PUBLIC') !== false];

        $key = parent::load($key, $password);
        if ($key === false) {
            return false;
        }

        $asn1 = new ASN1();
        $decoded = $asn1->decodeBER($key);
        if (empty($decoded)) {
            return false;
        }

        $key = $asn1->asn1map($decoded[0], RSAPrivateKey);
        if (is_array($key)) {
            $components+= [
                'modulus' => $key['modulus'],
                'publicExponent' => $key['publicExponent'],
                'privateExponent' => $key['privateExponent'],
                'primes' => [1 => $key['prime1'], $key['prime2']],
                'exponents' => [1 => $key['exponent1'], $key['exponent2']],
                'coefficients' => [2 => $key['coefficient']]
            ];
            if ($key['version'] == 'multi') {
                foreach ($key['otherPrimeInfos'] as $primeInfo) {
                    $components['primes'][] = $primeInfo['prime'];
                    $components['exponents'][] = $primeInfo['exponent'];
                    $components['coefficients'][] = $primeInfo['coefficient'];
                }
            }
            return $components;
        }

        $key = $asn1->asn1map($decoded[0], RSAPublicKey);

        return is_array($key) ? $components + $key : false;
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $n
     * @param \phpseclib\Math\BigInteger $e
     * @param \phpseclib\Math\BigInteger $d
     * @param array $primes
     * @param array $exponents
     * @param array $coefficients
     * @param string $password optional
     * @return string
     */
    static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, $primes, $exponents, $coefficients, $password = '')
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
            'coefficient' => $coefficients[2]
        ];
        for ($i = 3; $i <= $num_primes; $i++) {
            $key['otherPrimeInfos'][] = [
                'prime' => $primes[$i],
                'exponent' => $exponents[$i],
                'coefficient' => $coefficients[$i]
            ];
        }

        $asn1 = new ASN1();
        $key = $asn1->encodeDER($key, RSAPrivateKey);

        return self::wrapPrivateKey($key, 'RSA', $password);
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $n
     * @param \phpseclib\Math\BigInteger $e
     * @return string
     */
    static function savePublicKey(BigInteger $n, BigInteger $e)
    {
        $key = [
            'modulus' => $n,
            'publicExponent' => $e
        ];

        $asn1 = new ASN1();
        $key = $asn1->encodeDER($key, RSAPublicKey);

        return self::wrapPublicKey($key, 'RSA');
    }
}
