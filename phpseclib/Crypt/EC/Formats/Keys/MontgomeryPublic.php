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

namespace phpseclib4\Crypt\EC\Formats\Keys;

use phpseclib4\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib4\Crypt\EC\Curves\{Curve25519, Curve448};
use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\Math\BigInteger;
use phpseclib4\Math\Common\FiniteField\Integer;

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
     */
    public static function load(
        #[SensitiveParameter] string $key,
        #[SensitiveParameter] ?string $password = null
    ): array {
        $curve = match (strlen($key)) {
            32 => new Curve25519(),
            56 => new Curve448(),
            default => throw new UnexpectedValueException('The only supported lengths are 32 and 56')
        };

        $components = ['curve' => $curve];
        $components['QA'] = [$components['curve']->convertInteger(new BigInteger(strrev($key), 256))];

        return $components;
    }

    /**
     * Convert an EC public key to the appropriate format
     *
     * @param Integer[] $publicKey
     */
    public static function savePublicKey(MontgomeryCurve $curve, array $publicKey, array $options = []): string
    {
        return strrev($publicKey[0]->toBytes());
    }
}
