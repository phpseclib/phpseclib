<?php

/**
 * "PKCS1" (RFC5915) Formatted EC Key Handler
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
 * @package   EC
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\EC\Formats\Keys;

use phpseclib3\Math\Common\FiniteField\Integer;
use phpseclib3\Crypt\Common\Formats\Keys\PKCS1 as Progenitor;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Crypt\EC\BaseCurves\Base as BaseCurve;
use phpseclib3\Math\BigInteger;
use ParagonIE\ConstantTime\Base64;
use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib3\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib3\Exception\UnsupportedCurveException;

/**
 * "PKCS1" (RFC5915) Formatted EC Key Handler
 *
 * @package EC
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
     * Convert EC parameters to the appropriate format
     *
     * @access public
     * @return string
     */
    public static function saveParameters(BaseCurve $curve, array $options = [])
    {
        self::initialize_static_variables();

        if ($curve instanceof TwistedEdwardsCurve || $curve instanceof MontgomeryCurve) {
            throw new UnsupportedCurveException('TwistedEdwards and Montgomery Curves are not supported');
        }

        $key = self::encodeParameters($curve, false, $options);

        return "-----BEGIN EC PARAMETERS-----\r\n" .
               chunk_split(Base64::encode($key), 64) .
               "-----END EC PARAMETERS-----\r\n";
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @access public
     * @param \phpseclib3\Math\Common\FiniteField\Integer $privateKey
     * @param \phpseclib3\Crypt\EC\BaseCurves\Base $curve
     * @param \phpseclib3\Math\Common\FiniteField\Integer[] $publicKey
     * @param string $password optional
     * @param array $options optional
     * @return string
     */
    public static function savePrivateKey(Integer $privateKey, BaseCurve $curve, array $publicKey, $password = '', array $options = [])
    {
        self::initialize_static_variables();

        if ($curve instanceof TwistedEdwardsCurve  || $curve instanceof MontgomeryCurve) {
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

        return self::wrapPrivateKey($key, 'EC', $password, $options);
    }
}
