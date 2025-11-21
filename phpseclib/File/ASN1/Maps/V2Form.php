<?php

/**
 * V2Form
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
 * V2Form
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class V2Form
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'issuerName' => ['optional' => true] + GeneralNames::MAP,
            'baseCertificateID' => [
                'constant' => 0,
                'optional' => true,
            ] + IssuerSerial::MAP,
            'objectDigestInfo' => [
                'constant' => 1,
                'optional' => true,
            ] + ObjectDigestInfo::MAP,
        ],
    ];
}
