<?php

/**
 * LogotypeExtn
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
 * LogotypeExtn
 *
 * issuerLogo and subjectLogo share the same definition, so only their context
 * tag tells them apart. This extension MUST NOT be marked critical.
 *
 * https://datatracker.ietf.org/doc/html/rfc9399#appendix-A.1
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class LogotypeExtn
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'communityLogos' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'min' => 0,
                'max' => -1,
                'constant' => 0,
                'optional' => true,
                'explicit' => true,
                'children' => LogotypeInfo::MAP,
            ],
            'issuerLogo' => [
                'constant' => 1,
                'optional' => true,
                'explicit' => true,
            ] + LogotypeInfo::MAP,
            'subjectLogo' => [
                'constant' => 2,
                'optional' => true,
                'explicit' => true,
            ] + LogotypeInfo::MAP,
            'otherLogos' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'min' => 0,
                'max' => -1,
                'constant' => 3,
                'optional' => true,
                'explicit' => true,
                'children' => OtherLogotypeInfo::MAP,
            ],
        ],
    ];
}
