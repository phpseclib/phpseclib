<?php

/**
 * ASN.1 IA5 String
 *
 * International ASCII characters (International Alphabet 5)
 * https://en.wikipedia.org/wiki/T.50_(standard)
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
 * ASN.1 IA5 String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class IA5String extends BaseString
{
    public const TYPE = 22;
    protected const SIZE = 1;
}
