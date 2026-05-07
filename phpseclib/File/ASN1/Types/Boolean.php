<?php

/**
 * Boolean
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
