<?php

/**
 * Accuracy
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Maps;

use phpseclib4\File\ASN1;

/**
 * Accuracy
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Accuracy
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'seconds' => ['type' => ASN1::TYPE_INTEGER],
            'millis' => [
                'type' => ASN1::TYPE_INTEGER,
                'constant' => 0,
                'optional' => true,
                'implicit' => true,
            ],
            'micros' => [
                'type' => ASN1::TYPE_INTEGER,
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ],
        ],
    ];
}
