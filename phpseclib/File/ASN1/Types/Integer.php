<?php

/**
 * Integer
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

use phpseclib4\Math\BigInteger;

/**
 * Integer
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class Integer extends BigInteger implements BaseType
{
    use Common;

    public const TYPE = 2;

    public string $mappedValue;

    public function __debugInfo(): array
    {
        return isset($this->mappedValue) ?
            ['value' => $this->mappedValue] :
            parent::__debugInfo();
    }

    public function __toString(): string
    {
        return isset($this->mappedValue) ?
            $this->mappedValue :
            parent::__toString();
    }
}
