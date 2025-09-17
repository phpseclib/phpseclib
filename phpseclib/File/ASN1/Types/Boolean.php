<?php

/**
 * Boolean
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
 * Boolean
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class Boolean implements BaseType
{
    use Common;

    public const TYPE = 1;

    public function __construct(public bool $value)
    {
    }
}
