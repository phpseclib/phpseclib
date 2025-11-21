<?php

/**
 * Null
 *
 * Doing isset($a['key']) will return null if $a['key'] === null.
 * Sure, with an array, you could do array_key_exists(), instead, but
 * phpseclib is actually returning ArrayAccess objects - not arrays -
 * so that won't work.
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
 * Null
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class ExplicitNull implements BaseType
{
    use Common;

    public const TYPE = 5;
}
