<?php

/**
 * MacData
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
 * MacData
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class MacData
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'mac' => DigestInfo::MAP,
            'macSalt' => ['type' => ASN1::TYPE_OCTET_STRING],
            'iterations' => [
                'optional' => true,
                'implicit' => true,
                'default' => 1,
                'type' => ASN1::TYPE_INTEGER,
            ],
        ],
    ];
}
