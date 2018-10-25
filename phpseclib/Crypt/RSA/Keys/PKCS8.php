<?php

/**
 * PKCS#8 Formatted RSA Key Handler
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
 * @category  Crypt
 * @package   RSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\RSA\Keys;

use phpseclib\Math\BigInteger;
use phpseclib\Crypt\Common\Keys\PKCS8 as Progenitor;
use phpseclib\File\ASN1;

/**
 * PKCS#1 Formatted RSA Key Handler
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class PKCS8 extends Progenitor
{
    /**
     * OID Name
     *
     * @var string
     * @access private
     */
    const OID_NAME = 'rsaEncryption';

    /**
     * OID Value
     *
     * @var string
     * @access private
     */
    const OID_VALUE = '1.2.840.113549.1.1.1';

    /**
     * Child OIDs loaded
     *
     * @var bool
     * @access private
     */
    protected static $childOIDsLoaded = false;

    /**
     * Break a public or private key down into its constituent components
     *
     * @access public
     * @param string $key
     * @param string $password optional
     * @return array
     */
    public static function load($key, $password = '')
    {
        if (!is_string($key)) {
            throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        $components = ['isPublicKey' => strpos($key, 'PUBLIC') !== false];

        $key = parent::load($key, $password);

        $type = isset($key['privateKey']) ? 'private' : 'public';

        $result = $components + PKCS1::load($key[$type . 'Key']);

        if (isset($key['meta'])) {
            $result['meta'] = $key['meta'];
        }

        return $result;
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
        $key = PKCS1::savePrivateKey($n, $e, $d, $primes, $exponents, $coefficients);
        $key = ASN1::extractBER($key);
        return self::wrapPrivateKey($key, [], null, $password);
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
        $key = PKCS1::savePublicKey($n, $e);
        $key = ASN1::extractBER($key);
        return self::wrapPublicKey($key, null);
    }
}
