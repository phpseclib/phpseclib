<?php

/**
 * ASN.1 Videotex String
 *
 * CCITT's T.100 and T.101 character sets
 * https://en.wikipedia.org/wiki/Videotex_character_set
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Types;

/**
 * ASN.1 Videotex String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class VideotexString extends BaseString
{
    public const TYPE = 21;
}
