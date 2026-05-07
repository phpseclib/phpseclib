<?php

/**
 * Extensions
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
 * Extensions
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Extensions
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'min' => 1,
        // technically, it's MAX, but we'll assume anything < 0 is MAX
        'max' => -1,
        // if 'children' isn't an array then 'min' and 'max' must be defined
        'children' => Extension::MAP,
    ];
}
