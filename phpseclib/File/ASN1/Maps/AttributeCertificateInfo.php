<?php

/**
 * AttributeCertificateInfo
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
