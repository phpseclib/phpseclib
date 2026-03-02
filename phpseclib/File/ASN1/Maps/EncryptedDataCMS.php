<?php

/**
 * EncryptedDataCMS
 *
 * EncryptedData is defined differently in different RFCs.
 * RFC5652 (CMS) defines it one way:
 *
 * https://datatracker.ietf.org/doc/html/rfc5652#page-30
 *
 * RFC5208 (PKCS8) defines it another way:
 *
 * https://datatracker.ietf.org/doc/html/rfc5208#page-4
 *
 * This class implements the RFC5652 EncryptedData definition.
 *
 * The only difference between RFC5652's EncryptedData and RFC5652's EnvelopedData
 * is that EnvelopedData has originatorInfo (optional) and recipientInfos (required)
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
 * EncryptedDataCMS
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class EncryptedDataCMS
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => CMSVersion::MAP,
            'encryptedContentInfo' => EncryptedContentInfo::MAP,
            'unprotectedAttrs' => [
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ] + UnprotectedAttributes::MAP,
        ],
    ];
}
