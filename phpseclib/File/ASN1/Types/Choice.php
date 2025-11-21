<?php

/**
 * ASN.1 Choice
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

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;

/**
 * ASN.1 Choice
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class Choice implements \ArrayAccess, \Countable, \Iterator, BaseType
{
    public array $rules = [];
    public Choice|Constructed|null $parent = null;
    public int $depth = 0;
    public int|string $key;
    private string $rawheader = '';
    private string $encoded = '';
    private string $wrapping = '';
    private bool $forcedCache = false;
    private bool $iteratorStart = true;

    /**
     * Constructor
     *
     * @return Element
     */
    public function __construct(public string $index, public mixed $value)
    {
    }

    public function __debugInfo(): array
    {
        return [$this->index => $this->value];
    }

    public function enableForcedCache(): void
    {
        $this->forcedCache = true;
    }

    public function disableForcedCache(): void
    {
        $this->forcedCache = false;
    }

    public function isCacheForced(): bool
    {
        return $this->forcedCache;
    }

    public function setWrapping(string $wrapping): void
    {
        if ($this->value instanceof BaseType) {
            $this->value->setWrapping($wrapping);
        }
    }

    public function setEncoded(string $header, string $encoded): void
    {
        if ($this->value instanceof BaseType) {
            $this->value->setEncoded($header, $encoded);
        }
    }

    public function hasTypeID(): bool
    {
        return $this->value instanceof BaseType ? $this->value->hasTypeID() : false;
    }

    public function hasWrapping(): bool
    {
        return $this->value instanceof BaseType && $this->value->hasWrapping();
    }

    public function getEncodedWithWrapping(): string
    {
        return $this->value instanceof BaseType ? $this->value->getEncodedWithWrapping() : '';
    }

    public function hasEncoded(): bool
    {
        return $this->value instanceof BaseType && $this->value->hasEncoded();
    }

    public function getEncoded(): string
    {
        return $this->value instanceof BaseType ? $this->value->getEncoded() : '';
    }

    public function getEncodedLength(): int
    {
        return $this->value instanceof BaseType ? $this->value->getEncodedLength() : '';
    }

    public function offsetExists(mixed $offset): bool
    {
        return $offset == $this->index;
    }

    public function &offsetGet(mixed $offset): mixed
    {
        if ($offset != $this->index) {
            throw new RuntimeException("The requested offset '$offset' was not found");
            return $this->value;
        }
        if (($this->value instanceof Constructed || $this->value instanceof Choice) && !$this->value->parent) {
            $this->value->parent = $this;
            $this->value->depth = $this->depth + 1;
            $this->value->key = $this->key;
        }
        return $this->value;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        if (!Strings::is_stringable($offset)) {
            throw new RuntimeException('Only offsets that can be cast to strings are supported');
        }
        $this->index = "$offset";
        $this->value = $value;

        if (ASN1::invalidateCache()) {
            $this->invalidateCache();
        }
    }

    public function offsetUnset(mixed $offset): void
    {
        if ($offset == $this->index) {
            unset($this->index);
            unset($this->value);
        }
    }

    public function __toString(): string
    {
        if (!Strings::is_stringable($this->value)) {
            $reflect = new \ReflectionClass($this->value);
            throw new RuntimeException($reflect->getShortName() . ' isn\'t stringable');
        }
        return (string) $this->value;
    }

    public function count(): int
    {
        return 1;
    }

    public function toArray(bool $convertPrimitives = false): array
    {
        return $this->value instanceof Constructed || $this->value instanceof Choice ?
            [$this->index => $this->value->toArray($convertPrimitives)] :
            [$this->index => $convertPrimitives ? ASN1::convertToPrimitive($this->value) : $this->value];
    }

    public function invalidateCache(): void
    {
        $this->rawheader = '';
        $this->encoded = '';
        $this->wrapping = '';

        if ($this->parent) {
            $this->parent->invalidateCache();
        }
    }

    public function rewind(): void
    {
        $this->iteratorStart = true;
    }

    public function current(): mixed
    {
        return $this->value;
    }

    public function key(): mixed
    {
        return $this->index;
    }

    public function next(): void
    {
        $this->iteratorStart = false;
    }

    public function valid(): bool
    {
        return $this->iteratorStart;
    }
}
