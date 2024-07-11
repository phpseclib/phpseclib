<?php

/**
 * IEEE P1363 Signature Handler
 *
 * PHP version 5
 *
 * Handles signatures in the format described in
 * https://standards.ieee.org/ieee/1363/2049/ and
 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign#ecdsa
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\EC\Formats\Signature;

use phpseclib3\Math\BigInteger;

/**
 * ASN1 Signature Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class IEEE
{
    const PART_LENGTHS = [32, 48, 66];

    /**
     * Loads a signature
     *
     * @param string $sig
     * @return array
     */
    public static function load($sig)
    {
        if (!is_string($sig)) {
            return false;
        }

        $len = strlen($sig);
        if ($len & 1) {
            return false;
        }

        $r = new BigInteger(substr($sig, 0, $len >> 1), 256);
        $s = new BigInteger(substr($sig, $len >> 1), 256);

        return compact('r', 's');
    }

    /**
     * Returns a signature in the appropriate format
     */
    public static function save(BigInteger $r, BigInteger $s): string
    {
        $r = $r->toBytes();
        $s = $s->toBytes();
        $min = max(strlen($r), strlen($s));
        $len = array_reduce(static::PART_LENGTHS, function ($accumulator, $item) use ($min) {
            return $item >= $min && (null === $accumulator || $item < $accumulator) ? $item : $accumulator;
        });

        return str_pad($r, $len, "\0", STR_PAD_LEFT) . str_pad($s, $len, "\0", STR_PAD_LEFT);
    }
}
