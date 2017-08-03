<?php

/**
 * PKCS#8 Formatted DSA Key Handler
 *
 * PHP version 5
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
 * @package   DSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\DSA\Keys;

use phpseclib\Math\BigInteger;
use phpseclib\Crypt\Common\Keys\PKCS8 as Progenitor;
use phpseclib\File\ASN1;
use phpseclib\File\ASN1\Maps;

/**
 * PKCS#8 Formatted DSA Key Handler
 *
 * @package DSA
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
    const OID_NAME = 'id-dsa';

    /**
     * OID Value
     *
     * @var string
     * @access private
     */
    const OID_VALUE = '1.2.840.10040.4.1';

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
     * @return array|bool
     */
    public static function load($key, $password = '')
    {
        if (!is_string($key)) {
            return false;
        }

        $isPublic = strpos($key, 'PUBLIC') !== false;

        $key = parent::load($key, $password);
        if ($key === false) {
            return false;
        }

        $type = isset($key['privateKey']) ? 'privateKey' : 'publicKey';

        switch (true) {
            case !$isPublic && $type == 'publicKey':
            case $isPublic && $type == 'privateKey':
                return false;
        }

        $decoded = ASN1::decodeBER($key[$type . 'Algorithm']['parameters']->element);
        if (empty($decoded)) {
            return false;
        }
        $components = ASN1::asn1map($decoded[0], Maps\DSAParams::MAP);
        if (!is_array($components)) {
            return false;
        }

        $decoded = ASN1::decodeBER($key[$type]);
        if (empty($decoded)) {
            return false;
        }

        $var = $type == 'privateKey' ? 'x' : 'y';
        $components[$var] = ASN1::asn1map($decoded[0], Maps\DSAPublicKey::MAP);
        if (!$components[$var] instanceof BigInteger) {
            return false;
        }

        if (isset($key['meta'])) {
            $components['meta'] = $key['meta'];
        }

        return $components;
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
        $params = [
            'p' => $p,
            'q' => $q,
            'g' => $g
        ];
        $params = ASN1::encodeDER($params, Maps\DSAParams::MAP);
        $params = new ASN1\Element($params);
        $key = ASN1::encodeDER($x, Maps\DSAPublicKey::MAP);
        return self::wrapPrivateKey($key, [], $params, $password);
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
        $params = [
            'p' => $p,
            'q' => $q,
            'g' => $g
        ];
        $params = ASN1::encodeDER($params, Maps\DSAParams::MAP);
        $params = new ASN1\Element($params);
        $key = ASN1::encodeDER($y, Maps\DSAPublicKey::MAP);
        return self::wrapPublicKey($key, $params);
    }
}
