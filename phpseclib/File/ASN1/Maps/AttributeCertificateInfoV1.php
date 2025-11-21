<?php

/**
 * AttributeCertificateInfoV1
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
 * AttributeCertificateInfoV1
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class AttributeCertificateInfoV1
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => [
                'optional' => true,
                'default' => 'v1',
            ] + AttCertVersionV1::MAP,
            'subject' => [
                'type' => ASN1::TYPE_CHOICE,
                'children' => [
                    'baseCertificateID' => [
                        'constant' => 0,
                        'optional' => true,
                    ] + IssuerSerial::MAP,
                    'subjectName' => [
                        'constant' => 1,
                        'optional' => true,
                    ] + GeneralNames::MAP,
                ],
            ],
            'issuer' => GeneralNames::MAP,
            'signature' => AlgorithmIdentifier::MAP,
            'serialNumber' => CertificateSerialNumber::MAP,
            'attCertValidityPeriod' => AttCertValidityPeriod::MAP,
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
