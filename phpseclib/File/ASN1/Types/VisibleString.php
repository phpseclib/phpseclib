<?php

/**
 * ASN.1 Visible String
 *
 * International ASCII printing character sets
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
 * ASN.1 Visible String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class VisibleString extends BaseString
{
    public const TYPE = 26;
    protected const SIZE = 1;
}
