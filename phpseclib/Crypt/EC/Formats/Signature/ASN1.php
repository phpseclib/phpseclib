<?php

/**
 * ASN1 Signature Handler
 *
 * PHP version 5
 *
 * Handles signatures in the format described in
 * https://tools.ietf.org/html/rfc3279#section-2.2.3
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\EC\Formats\Signature;

use phpseclib3\File\ASN1 as Encoder;
use phpseclib3\File\ASN1\Maps\EcdsaSigValue;
use phpseclib3\Math\BigInteger;

/**
 * ASN1 Signature Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class ASN1
{
    /**
     * Loads a signature
     *
     * @return array
     */
    public static function load(string $sig): array
    {
        $decoded = Encoder::decodeBER($sig);
        $components = Encoder::map($decoded, EcdsaSigValue::MAP);

        return $components->toArray();
    }

    /**
     * Returns a signature in the appropriate format
     */
    public static function save(BigInteger $r, BigInteger $s): string
    {
        return Encoder::encodeDER(compact('r', 's'), EcdsaSigValue::MAP);
    }
}
