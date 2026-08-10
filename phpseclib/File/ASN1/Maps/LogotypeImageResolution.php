<?php

/**
 * LogotypeImageResolution
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
 * LogotypeImageResolution
 *
 * numBits is the resolution in bits, tableSize the number of colors or grey tones.
 *
 * https://datatracker.ietf.org/doc/html/rfc9399#appendix-A.1
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class LogotypeImageResolution
{
    public const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            'numBits' => [
                'type' => ASN1::TYPE_INTEGER,
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ],
            'tableSize' => [
                'type' => ASN1::TYPE_INTEGER,
                'constant' => 2,
                'optional' => true,
                'implicit' => true,
            ],
        ],
    ];
}
