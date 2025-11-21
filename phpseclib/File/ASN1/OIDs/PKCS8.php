<?php

/**
 * ASN.1 PKCS8 OIDs
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
 * PKCS8 OIDs
 *
 * From https://tools.ietf.org/html/rfc2898
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PKCS8
{
    public const OIDs = [
        // PBES1 encryption schemes
        'pbeWithMD2AndDES-CBC' => '1.2.840.113549.1.5.1',
        'pbeWithMD2AndRC2-CBC' => '1.2.840.113549.1.5.4',
        'pbeWithMD5AndDES-CBC' => '1.2.840.113549.1.5.3',
        'pbeWithMD5AndRC2-CBC' => '1.2.840.113549.1.5.6',
        'pbeWithSHA1AndDES-CBC' => '1.2.840.113549.1.5.10',
        'pbeWithSHA1AndRC2-CBC' => '1.2.840.113549.1.5.11',

        // from PKCS#12:
        // https://tools.ietf.org/html/rfc7292
        'pbeWithSHAAnd128BitRC4' => '1.2.840.113549.1.12.1.1',
        'pbeWithSHAAnd40BitRC4' => '1.2.840.113549.1.12.1.2',
        'pbeWithSHAAnd3-KeyTripleDES-CBC' => '1.2.840.113549.1.12.1.3',
        'pbeWithSHAAnd2-KeyTripleDES-CBC' => '1.2.840.113549.1.12.1.4',
        'pbeWithSHAAnd128BitRC2-CBC' => '1.2.840.113549.1.12.1.5',
        'pbeWithSHAAnd40BitRC2-CBC' => '1.2.840.113549.1.12.1.6',

        'id-PBKDF2' => '1.2.840.113549.1.5.12',
        'id-PBES2' => '1.2.840.113549.1.5.13',
        'id-PBMAC1' => '1.2.840.113549.1.5.14',

        // from PKCS#5 v2.1:
        // http://www.rsa.com/rsalabs/pkcs/files/h11302-wp-pkcs5v2-1-password-based-cryptography-standard.pdf
        'id-hmacWithSHA1' => '1.2.840.113549.2.7',
        'id-hmacWithSHA224' => '1.2.840.113549.2.8',
        'id-hmacWithSHA256' => '1.2.840.113549.2.9',
        'id-hmacWithSHA384' => '1.2.840.113549.2.10',
        'id-hmacWithSHA512' => '1.2.840.113549.2.11',
        'id-hmacWithSHA512-224' => '1.2.840.113549.2.12',
        'id-hmacWithSHA512-256' => '1.2.840.113549.2.13',

        'desCBC'       => '1.3.14.3.2.7',
        'des-EDE3-CBC' => '1.2.840.113549.3.7',
        'rc2CBC' => '1.2.840.113549.3.2',
        'rc5-CBC-PAD' => '1.2.840.113549.3.9',

        'aes128-CBC-PAD' => '2.16.840.1.101.3.4.1.2',
        'aes192-CBC-PAD' => '2.16.840.1.101.3.4.1.22',
        'aes256-CBC-PAD' => '2.16.840.1.101.3.4.1.42',
    ];
}