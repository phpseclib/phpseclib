<?php

/**
 * PKCS#1 Formatted DSA Key Handler
 *
 * PHP version 5
 *
 * Used by File/X509.php
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN DSA PRIVATE KEY-----
 * -----BEGIN DSA PUBLIC KEY-----
 * -----BEGIN DSA PARAMETERS-----
 *
 * Analogous to ssh-keygen's pem format (as specified by -m)
 *
 * @category  Crypt
 * @package   DSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\DSA\Keys;

use phpseclib\Math\BigInteger;
use phpseclib\Crypt\Common\Keys\PKCS1 as Progenitor;
use phpseclib\File\ASN1;
use phpseclib\File\ASN1\Maps;
use ParagonIE\ConstantTime\Base64;

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

        $key = parent::load($key, $password);
        if ($key === false) {
            return false;
        }

        $decoded = ASN1::decodeBER($key);
        if (empty($decoded)) {
            return false;
        }

        $key = ASN1::asn1map($decoded[0], Maps\DSAParams::MAP);
        if (is_array($key)) {
            return $key;
        }

        $key = ASN1::asn1map($decoded[0], Maps\DSAPrivateKey::MAP);
        if (is_array($key)) {
            return $key;
        }

        $key = ASN1::asn1map($decoded[0], Maps\DSAPublicKey::MAP);
        return is_array($key) ? $key : false;
    }

    /**
     * Convert DSA parameters to the appropriate format
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $p
     * @param \phpseclib\Math\BigInteger $q
     * @param \phpseclib\Math\BigInteger $g
     * @return string
     */
    public static function saveParameters(BigInteger $p, BigInteger $q, BigInteger $g)
    {
        $key = [
            'p' => $p,
            'q' => $q,
            'g' => $g
        ];

        $key = ASN1::encodeDER($key, Maps\DSAParams::MAP);

        return "-----BEGIN DSA PARAMETERS-----\r\n" .
               chunk_split(Base64::encode($key), 64) .
               "-----END DSA PARAMETERS-----\r\n";
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $p
     * @param \phpseclib\Math\BigInteger $q
     * @param \phpseclib\Math\BigInteger $g
     * @param \phpseclib\Math\BigInteger $x
     * @param \phpseclib\Math\BigInteger $y
     * @param string $password optional
     * @return string
     */
    public static function savePrivateKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, BigInteger $x, $password = '')
    {
        $key = [
            'version' => 0,
            'p' => $p,
            'q' => $q,
            'g' => $g,
            'y' => $y,
            'x' => $x
        ];

        $key = ASN1::encodeDER($key, Maps\DSAPrivateKey::MAP);

        return self::wrapPrivateKey($key, 'DSA', $password);
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $p
     * @param \phpseclib\Math\BigInteger $q
     * @param \phpseclib\Math\BigInteger $g
     * @param \phpseclib\Math\BigInteger $y
     * @return string
     */
    public static function savePublicKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y)
    {
        $key = ASN1::encodeDER($y, Maps\DSAPublicKey::MAP);

        return self::wrapPublicKey($key, 'DSA');
    }
}
