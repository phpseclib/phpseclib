<?php

/**
 * ExtendedCertificate
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
 * ExtendedCertificate
 *
 * mapping is from <ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-6.asc>
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class ExtendedCertificate
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'extendedCertificateInfo' => ExtendedCertificateInfo::MAP,
            'signatureAlgorithm' => AlgorithmIdentifier::MAP,
            'attributes' => ['type' => ASN1::TYPE_BIT_STRING],
        ],
    ];
}
