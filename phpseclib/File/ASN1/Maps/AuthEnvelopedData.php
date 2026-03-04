<?php

/**
 * AuthEnvelopedData
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
 * AuthEnvelopedData
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class AuthEnvelopedData
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => CMSVersion::MAP,
            'originatorInfo' => [
                'constant' => 0,
                'optional' => true,
                'implicit' => true,
            ] + OriginatorInfo::MAP,
            'recipientInfos' => RecipientInfos::MAP,
            'authEncryptedContentInfo' => EncryptedContentInfo::MAP,
            'authAttrs' => [
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ] + AuthAttributes::MAP,
            'mac' => MessageAuthenticationCode::MAP,
            'unauthAttrs' => [
                'constant' => 2,
                'optional' => true,
                'implicit' => true,
            ] + UnauthAttributes::MAP,
        ],
    ];
}
