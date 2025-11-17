<?php

/**
 * ASN.1 Base Type
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
 * ASN.1 Base Type
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
interface BaseType
{
    public function enableForcedCache(): void;
    public function disableForcedCache(): void;
    public function isCacheForced(): bool;
    public function setWrapping(string $wrapping): void;
    public function hasWrapping(): bool;
    public function getEncodedWithWrapping(): string;
    public function hasEncoded(): bool;
    public function getEncoded(): string;
    public function getEncodedLength(): int;
    public function setEncoded(string $header, string $encoded): void;
    public function hasTypeID(): bool;
}
