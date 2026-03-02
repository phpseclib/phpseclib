<?php

/**
 * PasswordRecipientInfo
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
 * PasswordRecipientInfo
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PasswordRecipientInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => CMSVersion::MAP,
            'keyDerivationAlgorithm' => [
                'constant' => 0,
                'optional' => true,
                'implicit' => true,
            ] + KeyDerivationAlgorithmIdentifier::MAP,
            'keyEncryptionAlgorithm' => KeyEncryptionAlgorithmIdentifier::MAP,
            'encryptedKey' => EncryptedKey::MAP,
        ],
    ];
}
