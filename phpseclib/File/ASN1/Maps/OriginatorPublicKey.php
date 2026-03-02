<?php

/**
 * OriginatorPublicKey
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
 * OriginatorPublicKey
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class OriginatorPublicKey
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'algorithm' => AlgorithmIdentifier::MAP,
            'publicKey' => ['type' => ASN1::TYPE_BIT_STRING],
        ],
    ];
}
