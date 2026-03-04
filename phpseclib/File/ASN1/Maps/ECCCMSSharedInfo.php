<?php

/**
 * ECCCMSSharedInfo
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
 * ECCCMSSharedInfo
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class ECCCMSSharedInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'keyInfo' => AlgorithmIdentifier::MAP,
            'entityUInfo' => [
                'type' => ASN1::TYPE_OCTET_STRING,
                'constant' => 0,
                'optional' => true,
                'explicit' => true,
            ],
            'suppPubInfo' => [
                'type' => ASN1::TYPE_OCTET_STRING,
                'constant' => 2,
                'optional' => true,
                'explicit' => true,
            ],
        ],
    ];
}
