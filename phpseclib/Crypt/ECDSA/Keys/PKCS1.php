<?php

/**
 * "PKCS1" (RFC5915) Formatted ECDSA Key Handler
 *
 * PHP version 5
 *
 * Used by File/X509.php
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN EC PRIVATE KEY-----
 * -----BEGIN EC PARAMETERS-----
 *
 * Technically, PKCS1 is for RSA keys, only, but we're using PKCS1 to describe
 * DSA, whose format isn't really formally described anywhere, so might as well
 * use it to describe this, too. PKCS1 is easier to remember than RFC5915, after
 * all. I suppose this could also be named IETF but idk
 *
 * @category  Crypt
 * @package   ECDSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\ECDSA\Keys;

use phpseclib\Math\Common\FiniteField\Integer;
use phpseclib\Crypt\Common\Keys\PKCS1 as Progenitor;
use phpseclib\File\ASN1;
use phpseclib\File\ASN1\Maps;
use phpseclib\Crypt\ECDSA\BaseCurves\Base as BaseCurve;
use phpseclib\Math\BigInteger;
use ParagonIE\ConstantTime\Base64;
use phpseclib\Crypt\ECDSA\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib\Exception\UnsupportedCurveException;

/**
 * "PKCS1" (RFC5915) Formatted ECDSA Key Handler
 *
 * @package ECDSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class PKCS1 extends Progenitor
{
    use Common;

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
        self::initialize_static_variables();

        $key = parent::load($key, $password);

        $decoded = ASN1::decodeBER($key);
        if (empty($decoded)) {
            throw new \RuntimeException('Unable to decode BER');
        }

        $key = ASN1::asn1map($decoded[0], Maps\ECParameters::MAP);
        if (is_array($key)) {
            return ['curve' => self::loadCurveByParam($key)];
        }

        $key = ASN1::asn1map($decoded[0], Maps\ECPrivateKey::MAP);
        if (!is_array($key)) {
            throw new \RuntimeException('Unable to perform ASN1 mapping');
        }

        $components = [];
        $components['curve'] = self::loadCurveByParam($key['parameters']);
        $temp = new BigInteger($key['privateKey'], 256);
        $components['dA'] = $components['curve']->convertInteger($temp);
        $components['QA'] = self::extractPoint($key['publicKey'], $components['curve']);

        return $components;
    }

    /**
     * Convert ECDSA parameters to the appropriate format
     *
     * @access public
     * @return string
     */
    public static function saveParameters(BaseCurve $curve)
    {
        self::initialize_static_variables();

        if ($curve instanceof TwistedEdwardsCurve) {
            throw new UnsupportedCurveException('TwistedEdwards Curves are not supported');
        }

        $key = self::encodeParameters($curve);

        return "-----BEGIN EC PARAMETERS-----\r\n" .
               chunk_split(Base64::encode($key), 64) .
               "-----END EC PARAMETERS-----\r\n";
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @access public
     * @param \phpseclib\Math\Common\FiniteField\Integer $privateKey
     * @param \phpseclib\Crypt\ECDSA\BaseCurves\Base $curve
     * @param \phpseclib\Math\Common\FiniteField\Integer[] $publicKey
     * @param string $password optional
     * @return string
     */
    public static function savePrivateKey(Integer $privateKey, BaseCurve $curve, array $publicKey, $password = '')
    {
        self::initialize_static_variables();

        if ($curve instanceof TwistedEdwardsCurve) {
            throw new UnsupportedCurveException('TwistedEdwards Curves are not supported');
        }

        $publicKey = "\4" . $publicKey[0]->toBytes() . $publicKey[1]->toBytes();

        $key = [
            'version' => 'ecPrivkeyVer1',
            'privateKey' => $privateKey->toBytes(),
            'parameters' => new ASN1\Element(self::encodeParameters($curve)),
            'publicKey' => "\0" . $publicKey
        ];

        $key = ASN1::encodeDER($key, Maps\ECPrivateKey::MAP);

        return self::wrapPrivateKey($key, 'EC', $password);
    }
}
