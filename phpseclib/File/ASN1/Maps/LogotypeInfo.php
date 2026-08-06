<?php

/**
 * LogotypeInfo
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
 * LogotypeInfo
 *
 * direct embeds the logotype data, indirect references it by hash and URI.
 *
 * https://datatracker.ietf.org/doc/html/rfc9399#appendix-A.1
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class LogotypeInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            'direct' => [
                'constant' => 0,
                'optional' => true,
                'implicit' => true,
            ] + LogotypeData::MAP,
            'indirect' => [
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ] + LogotypeReference::MAP,
        ],
    ];
}
