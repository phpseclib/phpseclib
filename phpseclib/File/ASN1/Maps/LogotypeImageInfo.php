<?php

/**
 * LogotypeImageInfo
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
 * LogotypeImageInfo
 *
 * fileSize is in octets, xSize and ySize are in pixels; 0 means unspecified.
 * language, when present, uses the syntax of RFC 5646.
 *
 * https://datatracker.ietf.org/doc/html/rfc9399#appendix-A.1
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class LogotypeImageInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'type' => [
                'constant' => 0,
                'optional' => true,
                'implicit' => true,
                'default' => 'color',
            ] + LogotypeImageType::MAP,
            'fileSize' => ['type' => ASN1::TYPE_INTEGER],
            'xSize' => ['type' => ASN1::TYPE_INTEGER],
            'ySize' => ['type' => ASN1::TYPE_INTEGER],
            'resolution' => ['optional' => true] + LogotypeImageResolution::MAP,
            'language' => [
                'type' => ASN1::TYPE_IA5_STRING,
                'constant' => 4,
                'optional' => true,
                'implicit' => true,
            ],
        ],
    ];
}
