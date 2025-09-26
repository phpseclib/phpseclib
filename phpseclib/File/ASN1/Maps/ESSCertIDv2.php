<?php

/**
 * ESSCertIDv2
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\File\ASN1\Maps;

use phpseclib3\File\ASN1;

/**
 * ESSCertIDv2
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class ESSCertIDv2
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'hashAlgorithm' => [
                'optional' => true,
                'default' => ['algorithm' => 'id-sha256', 'parameters' => null],
            ] + AlgorithmIdentifier::MAP,
            'certHash' => Hash::MAP,
            'issuerSerial' => ['optional' => true] + IssuerSerial::MAP,
        ],
    ];
}
