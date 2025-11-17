<?php

/**
 * ASN.1 Universal String
 *
 * ISO10646 character set
 * https://en.wikipedia.org/wiki/Universal_Coded_Character_Set
 *
 * "The character string type UniversalString supports any of the
 *  characters allowed by [ISO10646].  ISO 10646 is the Universal
 *  multiple-octet coded Character Set (UCS)."
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

namespace phpseclib3\File\ASN1\Types;

/**
 * ASN.1 Universal String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class UniversalString extends BaseString
{
    public const TYPE = 28;
    protected const SIZE = 4;
}
