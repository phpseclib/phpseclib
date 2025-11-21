<?php

/**
 * ASN.1 PSS OIDs
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
 * PSS OIDs
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Hashes
{
    public const OIDs = [
        'md2' => '1.2.840.113549.2.2',
        'md4' => '1.2.840.113549.2.4',
        'md5' => '1.2.840.113549.2.5',
        'id-sha1' => '1.3.14.3.2.26',
        'id-sha256' => '2.16.840.1.101.3.4.2.1',
        'id-sha384' => '2.16.840.1.101.3.4.2.2',
        'id-sha512' => '2.16.840.1.101.3.4.2.3',
        // from PKCS1 v2.2
        'id-sha224' => '2.16.840.1.101.3.4.2.4',
        'id-sha512/224' => '2.16.840.1.101.3.4.2.5',
        'id-sha512/256' => '2.16.840.1.101.3.4.2.6',

        'id-mgf1' => '1.2.840.113549.1.1.8',
    ];
}