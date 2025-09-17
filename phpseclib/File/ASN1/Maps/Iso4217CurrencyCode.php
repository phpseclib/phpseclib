<?php

/**
 * Iso4217CurrencyCode
 *
 * From https://www.etsi.org/deliver/etsi_ts/101800_101899/101862/01.03.02_60/ts_101862v010302p.pdf
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\File\ASN1\Maps;

use phpseclib3\File\ASN1;

/**
 * Iso4217CurrencyCode
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Iso4217CurrencyCode
{
    public const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            // Alphabetic or numeric currency code as defined in ISO 4217
            // It is recommended that the Alphabetic form is used
            'alphabetic' => ['type' => ASN1::TYPE_PRINTABLE_STRING], // Recommended (SIZE 3)
            'numeric' => ['type' => ASN1::TYPE_INTEGER], // 1..999
        ],
    ];
}
