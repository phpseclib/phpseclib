<?php

/**
 * PKCS Signature Handler
 *
 * PHP version 5
 *
 * Handles signatures in the format described in
 * https://tools.ietf.org/html/rfc3279#section-2.2.2
 *
 * @category  Crypt
 * @package   Common
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\DSA\Signature;

use phpseclib\Math\BigInteger;
use phpseclib\File\ASN1;
use phpseclib\File\ASN1\Maps;

/**
 * PKCS Signature Handler
 *
 * @package Common
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class PKCS
{
    /**
     * Loads a signature
     *
     * @access public
     * @param array $key
     * @return array
     */
    public static function load($sig)
    {
        if (!is_string($sig)) {
            return false;
        }

        $decoded = ASN1::decodeBER($sig);
        if (empty($decoded)) {
            return false;
        }
        $components = ASN1::asn1map($decoded[0], Maps\DssSigValue::MAP);

        return $components;
    }

    /**
     * Returns a signature in the appropriate format
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $r
     * @param \phpseclib\Math\BigInteger $s
     * @return string
     */
    public static function save(BigInteger $r, BigInteger $s)
    {
        return ASN1::encodeDER(compact('r', 's'), Maps\DssSigValue::MAP);
    }
}
