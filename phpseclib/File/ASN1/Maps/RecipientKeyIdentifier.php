<?php

/**
 * RecipientKeyIdentifier
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
 * RecipientKeyIdentifier
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class RecipientKeyIdentifier
{
    public const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            'subjectKeyIdentifier' => SubjectKeyIdentifier::MAP,
            'date' => [
                'type' => ASN1::TYPE_GENERALIZED_TIME,
                'optional' => true
            ],
            'other' => ['optional' => true] + OtherKeyAttribute::MAP,
        ],
    ];
}
