<?php

/**
 * OtherPrimeInfo
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Maps;

use phpseclib4\File\ASN1;

/**
 * OtherPrimeInfo
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class OtherPrimeInfo
{
    // version must be multi if otherPrimeInfos present
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'prime' => ['type' => ASN1::TYPE_INTEGER],      // ri
            'exponent' => ['type' => ASN1::TYPE_INTEGER],   // di
            'coefficient' => ['type' => ASN1::TYPE_INTEGER], // ti
        ],
    ];
}
