<?php

/**
 * SigningCertificateV2
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
 * SigningCertificateV2
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class SigningCertificateV2
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'certs' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'min' => 1,
                'max' => -1,
                'children' => ESSCertIDv2::MAP,
            ],
            'policies' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'min' => 1,
                'max' => -1,
                'children' => PolicyInformation::MAP,
                'optional' => true,
            ],
        ],
    ];
}
