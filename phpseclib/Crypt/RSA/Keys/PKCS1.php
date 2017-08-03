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

namespace phpseclib\Crypt\RSA\Keys;

use phpseclib\Math\BigInteger;
use phpseclib\Crypt\Common\Keys\PKCS1 as Progenitor;
use phpseclib\File\ASN1;
use phpseclib\File\ASN1\Maps;

/**
 * PKCS#1 Formatted RSA Key Handler
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class PKCS1 extends Progenitor
{
    /**
     * Break a public or private key down into its constituent components
     *
     * @access public
     * @param string $key
     * @param string $password optional
     * @return array|bool
     */
    public static function load($key, $password = '')
    {
        if (!is_string($key)) {
            return false;
        }

        $components = ['isPublicKey' => strpos($key, 'PUBLIC') !== false];

        $key = parent::load($key, $password);
        if ($key === false) {
            return false;
        }

        $decoded = ASN1::decodeBER($key);
        if (empty($decoded)) {
            return false;
        }

        $key = ASN1::asn1map($decoded[0], Maps\RSAPrivateKey::MAP);
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

        $key = ASN1::asn1map($decoded[0], Maps\RSAPublicKey::MAP);

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
    public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, $primes, $exponents, $coefficients, $password = '')
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

        $key = ASN1::encodeDER($key, Maps\RSAPrivateKey::MAP);

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
    public static function savePublicKey(BigInteger $n, BigInteger $e)
    {
        $key = [
            'modulus' => $n,
            'publicExponent' => $e
        ];

        $key = ASN1::encodeDER($key, Maps\RSAPublicKey::MAP);

        return self::wrapPublicKey($key, 'RSA');
    }
}
