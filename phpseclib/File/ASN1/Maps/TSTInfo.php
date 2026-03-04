<?php

/**
 * TSTInfo
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
 * TSTInfo
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class TSTInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => [
                'type' => ASN1::TYPE_INTEGER,
                'mapping' => ['v1'],
            ],
            'policy' => TSAPolicyId::MAP,
            'messageImprint' => MessageImprint::MAP,
            'serialNumber' => ['type' => ASN1::TYPE_INTEGER],
            'genTime' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
            'accuracy' => ['optional' => true] + Accuracy::MAP,
            'ordering' => [
                'type' => ASN1::TYPE_BOOLEAN,
                'optional' => true,
                'default' => false,
            ],
            'nonce' => [
                'type' => ASN1::TYPE_INTEGER,
                'optional' => true,
                'default' => -1,
            ],
            'tsa' => [
                'constant' => 0,
                'optional' => true,
                'explicit' => true,
            ] + GeneralName::MAP,
            'extensions' => [
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ] + Extensions::MAP,
        ],
    ];
}
