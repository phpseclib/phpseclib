<?php

/**
 * ASN.1 Printable String
 *
 * "The character string type PrintableString supports a very basic Latin
 *  character set: the lowercase letters 'a' through 'z', uppercase
 *  letters 'A' through 'Z', the digits '0' through '9', eleven special
 *  characters ' = ( ) + , - . / : ? and space.
 *
 *  Implementers should note that the at sign ('@') and underscore ('_')
 *  characters are not supported by the ASN.1 type PrintableString."
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
 * ASN.1 Printable String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class PrintableString extends BaseString
{
    public const TYPE = 19;
    protected const SIZE = 1;
}
