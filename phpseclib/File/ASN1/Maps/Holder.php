<?php

/**
 * Holder
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
 * Holder
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Holder
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'baseCertificateID' => [
                'constant' => 0,
                'optional' => true,
            ] + IssuerSerial::MAP,
            'entityName' => [
                'constant' => 1,
                'optional' => true,
            ] + GeneralNames::MAP,
            'objectDigestInfo' => [
                'constant' => 2,
                'optional' => true,
            ] + ObjectDigestInfo::MAP,
        ],
    ];
}
