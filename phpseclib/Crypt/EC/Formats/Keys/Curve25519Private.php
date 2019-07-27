<?php

/**
 * Curve25519 Private Key Handler
 *
 * "Naked" Curve25519 private keys can pretty much be any sequence of random 32x bytes so unless
 * we have a "hidden" key handler pretty much every 32 byte string will be loaded as a curve25519
 * private key even if it probably isn't one by PublicKeyLoader.
 *
 * "Naked" Curve25519 public keys also a string of 32 bytes so distinguishing between a "naked"
 * curve25519 private key and a public key is nigh impossible, hence separate plugins for each
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
 * Curve25519 Private Key Handler
 *
 * @package EC
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class Curve25519Private
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
        $components['dA'] = $components['curve']->convertInteger(new BigInteger($key, -256));
        // note that EC::getEncodedCoordinates does some additional "magic" (it does strrev on the result)
        $components['QA'] = $components['curve']->multiplyPoint($components['curve']->getBasePoint(), $components['dA']);

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

    /**
     * Convert a private key to the appropriate format.
     *
     * @access public
     * @param \phpseclib\Math\Common\FiniteField\Integer $privateKey
     * @param \phpseclib\Crypt\EC\Curves\Curve25519 $curve
     * @param \phpseclib\Math\Common\FiniteField\Integer[] $publicKey
     * @param string $password optional
     * @return string
     */
    public static function savePrivateKey(Integer $privateKey, Curve25519 $curve, array $publicKey, $password = '')
    {
        return $privateKey->toBytes(true);
    }
}
