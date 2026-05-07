<?php

/**
 * ASN.1 Numeric String
 *
 * 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, and SPACE
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Types;

/**
 * ASN.1 Numeric String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class NumericString extends BaseString
{
    public const TYPE = 18;
}
