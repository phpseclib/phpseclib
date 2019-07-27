<?php

/**
 * Curve25519 Public Key Handler
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
use phpseclib\Math\Common\FiniteField\Integer;
use phpseclib\Math\BigInteger;

/**
 * Curve25519 Public Key Handler
 *
 * @package EC
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class Curve25519Public
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
        $curve = new Curve25519();

        $components = ['curve' => $curve];
        $components['QA'] = [$components['curve']->convertInteger(new BigInteger(strrev($key), -256))];

        return $components;
    }

    /**
     * Convert an EC public key to the appropriate format
     *
     * @access public
     * @param \phpseclib\Crypt\EC\Curves\Curve25519 $curve
     * @param \phpseclib\Math\Common\FiniteField\Integer[] $publicKey
     * @return string
     */
    public static function savePublicKey(Curve25519 $curve, array $publicKey)
    {
        return strrev($publicKey[0]->toBytes(true));
    }
}
