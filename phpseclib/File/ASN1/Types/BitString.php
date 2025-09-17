<?php

/**
 * ASN.1 Bit String
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

use phpseclib3\Exception\RuntimeException;

/**
 * ASN.1 Bit String
 *
 * The use of the \ArrayAccess, \Countable and \Iterator interfaces is due to stuff like
 * \phpseclib3\File\ASN1\Maps\KeyUsage
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class BitString extends BaseString implements \ArrayAccess, \Countable, \Iterator
{
    public array $mappedValue;
    public const TYPE = 4;

    private function preCheck()
    {
        if (!isset($this->mappedValue)) {
            throw new RuntimeException('mappedValue needs to be set for this functionality to be used');
        }
    }

    public function contains(string $key): bool
    {
        $this->preCheck();
        return in_array($key, $this->mappedValue);
    }

    public function offsetExists(mixed $offset): bool
    {
        $this->preCheck();
        return isset($this->mappedValue[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        $this->preCheck();
        return $this->mappedValue[$offset];
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->preCheck();
        $this->mappedValue[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        $this->preCheck();
        unset($this->mappedValue[$offset]);
    }

    public function count(): int
    {
        $this->preCheck();
        return count($this->mappedValue);
    }

    public function current(): mixed
    {
        $this->preCheck();
        return current($this->mappedValue);
    }

    public function key(): mixed
    {
        $this->preCheck();
        return key($this->mappedValue);
    }

    public function next(): void
    {
        $this->preCheck();
        next($this->mappedValue);
    }

    public function rewind(): void
    {
        $this->preCheck();
        rewind($this->mappedValue);
    }

    public function valid(): bool
    {
        $this->preCheck();
        return isset($this->mappedValue[key($this->mappedValue)]);
    }

    public function toArray(): array
    {
        $this->preCheck();
        return $this->mappedValue;
    }

    public function __debugInfo(): array
    {
        return isset($this->mappedValue) ?
            $this->mappedValue :
            ['value' => bin2hex($this->value)];
    }
}
