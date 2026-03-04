<?php
/**
 * Pure-PHP CMS / DigestedData Parser
 *
 * PHP version 8
 *
 * Encode and decode CMS / DigestedData files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\CMS;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\Hash;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Element;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\ASN1\Types\OctetString;
use phpseclib4\File\CMS;

/**
 * Pure-PHP CMS / DigestedData Parser
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class DigestedData implements \ArrayAccess, \Countable, \Iterator
{
    private Constructed|array $cms;

    /**
     * @param string $data
     */
    public function __construct(string $data, $hashAlgorithm = 'sha256')
    {
        ASN1::loadOIDs('Hashes');
        $hash = new Hash($hashAlgorithm);
        if (substr($hashAlgorithm, 0, 2) != 'md') {
            $hashAlgorithm = "id-$hashAlgorithm";
        }
        $this->cms = [
            'contentType' => 'id-digestedData',
            'content' => [
                // "If the encapsulated content type is id-data, then the value of version MUST be 0; however, if
                //  the encapsulated content type is other than id-data, then the value of version MUST be 2."
                'version' => 'v0',
                'digestAlgorithm' => ['algorithm' => $hashAlgorithm],
                'encapContentInfo' => [
                    'eContentType' => 'id-data',
                    'eContent' => new OctetString($data),
                ],
                'digest' => $hash->hash($data),
            ]
        ];
    }

    // CMS::load() takes care of the PEM / DER encoding toggling
    // if you want to load an array or Constructed as a SignedData instance you'll
    // need to call CMS\SignedData::load()
    public static function load(string|array|Constructed $encoded): self
    {
        $r = new \ReflectionClass(__CLASS__);
        $cms = $r->newInstanceWithoutConstructor();
        $cms->cms = is_string($encoded) ? self::loadString($encoded) : $encoded;
        return $cms;
    }

    private static function loadString(string $encoded): Constructed
    {
        $decoded = ASN1::decodeBER($encoded);
        $cms = ASN1::map($decoded, Maps\ContentInfo::MAP);
        $decoded = ASN1::decodeBER($cms['content']->value);
        $cms['content'] = ASN1::map($decoded, Maps\DigestedData::MAP);
        $cms['content']->parent = $cms;
        $cms['content']->key = 'content';
        return $cms;
    }

    public function &offsetGet(mixed $offset): mixed
    {
        $this->compile();
        return $this->cms[$offset];
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->cms[$offset]);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->cms[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->cms[$offset]);
    }

    public function count(): int
    {
        return is_array($this->cms) ? count($this->cms) : $this->cms->count();
    }

    public function rewind(): void
    {
        $this->compile();
        $this->cms->rewind();
    }

    public function current(): mixed
    {
        $this->compile();
        return $this->cms->current();
    }

    public function key(): mixed
    {
        $this->compile();
        return $this->cms->key();
    }

    public function next(): void
    {
        $this->compile();
        $this->cms->next();
    }

    public function valid(): bool
    {
        $this->compile();
        return $this->cms->valid();
    }

    public function toString(array $options = []): string
    {
        if ($this->cms instanceof Constructed) {
            ASN1::encodeDER($this->cms['content'], Maps\DigestedData::MAP);
            $cms = ASN1::encodeDER($this->cms, Maps\ContentInfo::MAP);
        } else {
            $temp = [
                'contentType' => $this->cms['contentType'], // 99% of the time this'll be 'id-digestedData'
                'content' => new Element(ASN1::encodeDER($this->cms['content'], Maps\DigestedData::MAP)),
            ];
            $cms = ASN1::encodeDER($temp, Maps\ContentInfo::MAP);
            $this->cms = self::load($cms)->cms;
        }

        if ($options['binary'] ?? CMS::$binary) {
            return $cms;
        }

        return "-----BEGIN CMS-----\r\n" . chunk_split(Strings::base64_encode($cms), 64) . '-----END CMS-----';
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function compile(): void
    {
        if (!$this->cms instanceof Constructed || !$this->cms->hasEncoded()) {
            $temp = self::load($this->toString(['binary' => true]));
            $this->cms = $temp->cms;
        }
    }

    public function __debugInfo(): array
    {
        $this->compile();
        return $this->cms->__debugInfo();
    }

    public function validate(): bool
    {
        $hash = new Hash(str_replace('id-', '', (string) $this->cms['content']['digestAlgorithm']['algorithm']));
        $actual = $hash->hash((string) $this->cms['content']['encapContentInfo']['eContent']);
        $expected = (string) $this->cms['content']['digest'];
        return hash_equals($actual, $expected);
    }

    public function toArray(bool $convertPrimitives = false): array
    {
        $this->compile();
        return $this->cms instanceof Constructed ? $this->cms->toArray($convertPrimitives) : $this->cms;
    }
}