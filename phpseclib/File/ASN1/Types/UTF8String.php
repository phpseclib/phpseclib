<?php

/**
 * ASN.1 UTF8 String
 *
 * any character from a recognized alphabet (including ASCII control characters)
 * https://en.wikipedia.org/wiki/UTF-8
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
 * ASN.1 UTF8 String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class UTF8String extends BaseString
{
    public const TYPE = 12;
    protected const SIZE = 0;
}
