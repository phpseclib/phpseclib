<?php

/**
 * ASN.1 CMS OIDs
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
 * CMS OIDs
 *
 * OIDs from RFC5652
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class CMS
{
    public const OIDs = [
        'id-data' => '1.2.840.113549.1.7.1', // section 4
        'id-signedData' => '1.2.840.113549.1.7.2', // section 5
        'id-ct-compressedData' => '1.2.840.113549.1.9.16.1.9', // section 1.1
        'id-envelopedData' => '1.2.840.113549.1.7.3', // section 6
        'id-digestedData' => '1.2.840.113549.1.7.5', // section 7
        'id-encryptedData' => '1.2.840.113549.1.7.6', // section 8
        'id-ct-authData' => '1.2.840.113549.1.9.16.1.2', // section 9

        'id-contentType' => '1.2.840.113549.1.9.3', // section 11.1
        'id-messageDigest' => '1.2.840.113549.1.9.4', // section 11.2
        'id-signingTime' => '1.2.840.113549.1.9.5', // section 11.3
        'id-countersignature' => '1.2.840.113549.1.9.6', // section 11.3

        'pkcs-9-at-smimeCapabilities' => '1.2.840.113549.1.9.15', // https://tools.ietf.org/html/rfc2985

        'id-aa-signingCertificate' => '1.2.840.113549.1.9.16.2.12', // https://tools.ietf.org/html/rfc2634#section-5.4
        'id-aa-signingCertificateV2' => '1.2.840.113549.1.9.16.2.47', // https://tools.ietf.org/html/rfc5035#section-3

        'id-aa-contentIdentifier' => '1.2.840.113549.1.9.16.2.7',

        'id-alg-zlibCompress' => '1.2.840.113549.1.9.16.3.8', // from RFC3274
    ];
}