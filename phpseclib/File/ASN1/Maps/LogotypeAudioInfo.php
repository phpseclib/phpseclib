<?php

/**
 * LogotypeAudioInfo
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
 * LogotypeAudioInfo
 *
 * fileSize is in octets, playTime in milliseconds, channels is 1 for mono,
 * 2 for stereo and 4 for quad. sampleRate is in samples per second and
 * language, when present, uses the syntax of RFC 5646.
 *
 * https://datatracker.ietf.org/doc/html/rfc9399#appendix-A.1
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class LogotypeAudioInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'fileSize' => ['type' => ASN1::TYPE_INTEGER],
            'playTime' => ['type' => ASN1::TYPE_INTEGER],
            'channels' => ['type' => ASN1::TYPE_INTEGER],
            'sampleRate' => [
                'type' => ASN1::TYPE_INTEGER,
                'constant' => 3,
                'optional' => true,
                'implicit' => true,
            ],
            'language' => [
                'type' => ASN1::TYPE_IA5_STRING,
                'constant' => 4,
                'optional' => true,
                'implicit' => true,
            ],
        ],
    ];
}
