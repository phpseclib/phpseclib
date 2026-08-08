<?php

/**
 * LogotypeReference
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
 * LogotypeReference
 *
 * https://datatracker.ietf.org/doc/html/rfc9399#appendix-A.1
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class LogotypeReference
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'refStructHash' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'min' => 1,
                'max' => -1,
                'children' => HashAlgAndValue::MAP,
            ],
            'refStructURI' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'min' => 1,
                'max' => -1,
                'children' => ['type' => ASN1::TYPE_IA5_STRING],
            ],
        ],
    ];
}
