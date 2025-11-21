<?php

/**
 * ASN.1 Videotex String
 *
 * CCITT's T.100 and T.101 character sets
 * https://en.wikipedia.org/wiki/Videotex_character_set
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2012 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
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
