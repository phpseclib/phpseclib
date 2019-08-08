<?php

/**
 * Montgomery Public Key Handler
 *
 * PHP version 5
 *
 * @category  Crypt
 * @package   EC
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\EC\Formats\Keys;

use phpseclib\Crypt\EC\Curves\Curve25519;
use phpseclib\Crypt\EC\Curves\Curve448;
use phpseclib\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib\Math\Common\FiniteField\Integer;
use phpseclib\Math\BigInteger;

/**
 * Montgomery Public Key Handler
 *
 * @package EC
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class MontgomeryPublic
{
    /**
     * Is invisible flag
     *
     * @access private
     */
    const IS_INVISIBLE = true;

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
        switch (strlen($key)) {
            case 32:
                $curve = new Curve25519;
                break;
            case 56:
                $curve = new Curve448;
                break;
            default:
                throw new \LengthException('The only supported lengths are 32 and 56');
        }

        $components = ['curve' => $curve];
        $components['QA'] = [$components['curve']->convertInteger(new BigInteger(strrev($key), 256))];

        return $components;
    }

    /**
     * Convert an EC public key to the appropriate format
     *
     * @access public
     * @param \phpseclib\Crypt\EC\Curves\Montgomery $curve
     * @param \phpseclib\Math\Common\FiniteField\Integer[] $publicKey
     * @return string
     */
    public static function savePublicKey(MontgomeryCurve $curve, array $publicKey)
    {
        return strrev($publicKey[0]->toBytes());
    }
}
