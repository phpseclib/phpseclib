<?php

/**
 * ASN.1 Visible String
 *
 * International ASCII printing character sets
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
 * ASN.1 Visible String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class VisibleString extends BaseString
{
    public const TYPE = 26;
    protected const SIZE = 1;
}
