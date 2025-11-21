<?php

/**
 * ASN.1 Teletex String
 *
 * CCITT and T.101 character sets
 * https://en.wikipedia.org/wiki/Teletext_character_set
 *
 * "The character string type TeletexString is a superset of
 *  PrintableString.  TeletexString supports a fairly standard (ASCII-
 *  like) Latin character set: Latin characters with non-spacing accents
 *  and Japanese characters."
 * -- RFC5280, Appendix B. ASN.1 Notes
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
 * ASN.1 Teletex String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class TeletexString extends BaseString
{
    public const TYPE = 20;
    protected const SIZE = 1;
}
