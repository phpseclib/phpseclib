<?php

/**
 * Integer
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2025-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
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
        return $this->mappedValue ?? parent::__toString();
    }
}
