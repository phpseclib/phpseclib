<?php

/**
 * CMSEncryptedData
 *
 * This is using the RFC5652 (CMS) definition of EncryptedData:
 * https://datatracker.ietf.org/doc/html/rfc5652#section-8
 *
 * RFC5208 (PKCS#8) has another definition of EncryptedData:
 * https://datatracker.ietf.org/doc/html/rfc5208#section-6
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
 * CMSEncryptedData
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class CMSEncryptedData
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => CMSVersion::MAP,
            'encryptedContentInfo' => EncryptedContentInfo::MAP,
            'unprotectedAttrs' => [
                'constant' => 1,
                'optional' => true,
                'implicit' => true
            ] + UnprotectedAttributes::MAP,
        ]
    ];
}
