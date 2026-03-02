<?php

/**
 * KeyAgreeRecipientInfo
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
 * KeyAgreeRecipientInfo
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class KeyAgreeRecipientInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => CMSVersion::MAP,
            'originator' => [
                'constant' => 0,
                'optional' => true,
                'explicit' => true,
            ] + OriginatorIdentifierOrKey::MAP,
            'ukm' => [
                'constant' => 1,
                'optional' => true,
                'explicit' => true,
            ] + UserKeyingMaterial::MAP,
            'keyEncryptionAlgorithm' => KeyEncryptionAlgorithmIdentifier::MAP,
            'recipientEncryptedKeys' => RecipientEncryptedKeys::MAP,
        ],
    ];
}
