<?php

/**
 * ML-DSA-PrivateKey
 *
 * See https://www.rfc-editor.org/rfc/rfc9881#section-6
 *
 * PHP version 8.1+
 *
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Maps;

use phpseclib4\File\ASN1;

/**
 * ML-DSA-PrivateKey
 *
 * This is the content of the privateKey OCTET STRING of a OneAsymmetricKey (PKCS#8)
 *
 * @author  Adriel Cavalcante
 */
abstract class MLDSAPrivateKey
{
    public const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            'seed' => [
                'type' => ASN1::TYPE_OCTET_STRING,
                'constant' => 0,
                'optional' => true,
                'implicit' => true,
            ],
            'expandedKey' => ['type' => ASN1::TYPE_OCTET_STRING],
            'both' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'seed' => ['type' => ASN1::TYPE_OCTET_STRING],
                    'expandedKey' => ['type' => ASN1::TYPE_OCTET_STRING],
                ],
            ],
        ],
    ];
}
