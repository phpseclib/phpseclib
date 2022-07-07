<?php

/**
 * Montgomery Public Key Handler
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\EC\Formats\Keys;

use phpseclib3\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib3\Crypt\EC\Curves\Curve25519;
use phpseclib3\Crypt\EC\Curves\Curve448;
use phpseclib3\Math\BigInteger;

/**
 * Montgomery Public Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class MontgomeryPublic
{
    /**
     * Is invisible flag
     */
    public const IS_INVISIBLE = true;

    /**
     * Break a public or private key down into its constituent components
     *
     * @param string|false $password
     */
    public static function load(string $key, $password = ''): array
    {
        switch (strlen($key)) {
            case 32:
                $curve = new Curve25519();
                break;
            case 56:
                $curve = new Curve448();
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
     * @param \phpseclib3\Math\Common\FiniteField\Integer[] $publicKey
     */
    public static function savePublicKey(MontgomeryCurve $curve, array $publicKey): string
    {
        return strrev($publicKey[0]->toBytes());
    }
}
