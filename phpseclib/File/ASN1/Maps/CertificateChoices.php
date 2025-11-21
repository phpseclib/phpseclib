<?php

/**
 * CertificateChoices
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
 * CertificateChoices
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class CertificateChoices
{
    public const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            'certificate' => Certificate::MAP,
            'extendedCertificate' => [
                'constant' => 0,
                'optional' => true,
                'implicit' => true,
            ] + ExtendedCertificate::MAP,
            'v1AttrCert' => [
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ] + AttributeCertificateV1::MAP,
            'v2AttrCert' => [
                'constant' => 2,
                'optional' => true,
                'implicit' => true,
            ] + AttributeCertificateV2::MAP,
            'other' => [
                'constant' => 3,
                'optional' => true,
                'implicit' => true,
            ] + OtherCertificateFormat::MAP,
        ],
    ];
}
