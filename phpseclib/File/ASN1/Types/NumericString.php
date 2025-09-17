<?php

/**
 * ASN.1 Numeric String
 *
 * 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, and SPACE
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
 * ASN.1 Numeric String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class NumericString extends BaseString
{
    public const TYPE = 18;
}
