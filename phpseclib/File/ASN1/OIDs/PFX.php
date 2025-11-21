<?php

/**
 * ASN.1 PFX (PKCS#12) OIDs
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\OIDs;

/**
 * ASN.1 PFX (PKCS#12) OIDs
 *
 * OIDs from RFC7292
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PFX
{
    public const OIDs = [
        'KeyBag' => '1.2.840.113549.1.12.10.1.1',
        'PKCS8ShroudedKeyBag' => '1.2.840.113549.1.12.10.1.2',
        'CertBag' => '1.2.840.113549.1.12.10.1.3',
        'CRLBag' => '1.2.840.113549.1.12.10.1.4',
        'SecretBag' => '1.2.840.113549.1.12.10.1.5',
        'SafeContents' => '1.2.840.113549.1.12.10.1.6',
        'x509Certificate' => '1.2.840.113549.1.9.22.1',
        'pkcs-9-at-friendlyName' => '1.2.840.113549.1.9.20',
        'pkcs-9-at-localKeyId' => '1.2.840.113549.1.9.21',
        // https://www.rfc-editor.org/rfc/rfc7292#section-4.2.3 defines the following:
        //'x509Certificate' => '1.2.840.113549.1.9.0.1.1',
        //'sdsiCertificate' => '1.2.840.113549.1.9.0.1.2',
        // near as i can tell, however, nothing actually uses those OIDs
    ];
}