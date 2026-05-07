<?php

/**
 * RecipientIdentifier
 *
 * Basically the same thing as SignerIdentifier
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
 * RecipientIdentifier
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class RecipientIdentifier
{
    public const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            'issuerAndSerialNumber' => IssuerAndSerialNumber::MAP,
            'subjectKeyIdentifier' => [
                'constant' => 0,
                'optional' => true,
                'explicit' => true,
            ] + SubjectKeyIdentifier::MAP,
        ],
    ];
}
