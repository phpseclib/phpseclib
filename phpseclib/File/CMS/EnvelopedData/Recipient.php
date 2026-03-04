<?php
/**
 * Pure-PHP CMS / PasswordRecipient Parser
 *
 * PHP version 8
 *
 * Encode and decode CMS / EnvelopedData / PasswordRecipient files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\CMS\EnvelopedData;

use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Types\Choice;
use phpseclib4\File\CMS\EncryptedData;

class Recipient implements \ArrayAccess, \Countable, \Iterator
{
    use \phpseclib4\File\Common\Traits\KeyDerivation;

    public Constructed|array|null $recipient;
    public ?EncryptedData $cms = null;
    public ?Choice $parent;
    public int $depth = 0;
    public int|string $key;

    public function __construct(Constructed|array|null $recipient = null)
    {
        $this->recipient = $recipient;
    }

    public static function load(string|array|Constructed $encoded): static
    {
        $recipient = new static();
        $recipient->recipient = is_string($encoded) ? static::loadString($encoded) : $encoded;
        return $recipient;
    }

    public function compile(): void
    {
        if (!$this->recipient instanceof Constructed) {
            $temp = self::load("$this");
            $this->recipient = $temp->recipient;
            return;
        }
        if ($this->recipient->hasEncoded()) {
            return;
        }
        $oldParent = $this->recipient->parent;
        $temp = self::load("$this");
        $this->recipient = $temp->recipient;
        $this->recipient->parent = $oldParent;
    }

    public function getEncoded(): string
    {
        $this->compile();
        return $this->recipient->getEncoded();
    }

    public function &offsetGet(mixed $offset): mixed
    {
        $this->compile();
        return $this->recipient[$offset];
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->recipient[$offset]);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->recipient[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->recipient[$offset]);
    }

    public function count(): int
    {
        return is_array($this->recipient) ? count($this->recipient) : $this->recipient->count();
    }

    public function rewind(): void
    {
        $this->compile();
        $this->recipient->rewind();
    }

    public function current(): mixed
    {
        $this->compile();
        return $this->recipient->current();
    }

    public function key(): mixed
    {
        $this->compile();
        return $this->recipient->key();
    }

    public function next(): void
    {
        $this->compile();
        $this->recipient->next();
    }

    public function valid(): bool
    {
        $this->compile();
        return $this->recipient->valid();
    }

    public function keys(): array
    {
        return $this->recipient instanceof Constructed ? $this->recipient->keys() : array_keys($this->recipient);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function __debugInfo(): array
    {
        $this->compile();
        return $this->recipient->__debugInfo();
    }

    public function toArray(bool $convertPrimitives = false): array
    {
        $this->compile();
        return $this->recipient instanceof Constructed ? $this->recipient->toArray($convertPrimitives) : $this->recipient;
    }
}