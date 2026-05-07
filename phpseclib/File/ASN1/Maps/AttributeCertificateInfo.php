<?php

/**
 * AttributeCertificateInfo
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
 * AttributeCertificateInfo
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class AttributeCertificateInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => [
                'optional' => true,
                'default' => 'v2',
            ] + AttCertVersion::MAP,
            'holder' => Holder::MAP,
            'issuer' => AttCertIssuer::MAP,
            'signature' => AlgorithmIdentifier::MAP,
            'serialNumber' => CertificateSerialNumber::MAP,
            'attrCertValidityPeriod' => AttCertValidityPeriod::MAP,
            'attributes' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'min' => 0,
                'max' => -1,
                'children' => Attribute::MAP,
            ],
            'issuerUniqueID' => ['optional' => true] + UniqueIdentifier::MAP,
            'extensions' => ['optional' => true] + Extensions::MAP,
        ],
    ];
}
