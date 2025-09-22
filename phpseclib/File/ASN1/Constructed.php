<?php

/**
 * ASN.1 Constructed Array Object
 *
 * Load the 'content' array key of constructed array objects on-demand.
 *
 * Does not implement ArrayObject. Altho this class implements all the same interfaces
 * that ArrayObject implements, ArrayObject adds additional functions that really
 * don't make a lot of sense in the context of phpseclib. eg. asort(), ksort(), etc.
 * offsetSet() kinda makes append() redundant as well.
 *
 * PHP version 8
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\File\ASN1;

use phpseclib3\Exception\EncodedDataUnavailableException;
use phpseclib3\Exception\EOCException;
use phpseclib3\Exception\ExcessivelyDeepDataException;
use phpseclib3\Exception\InsufficientSetupException;
use phpseclib3\Exception\NoValidTagFoundException;
use phpseclib3\Exception\RuntimeException;
use phpseclib3\File\ASN1;
use phpseclib3\File\X509;
use phpseclib3\File\ASN1\Element;
use phpseclib3\File\ASN1\ExcessivelyDeepData;
use phpseclib3\File\ASN1\MalformedData;
use phpseclib3\File\ASN1\Types\BaseString;
use phpseclib3\File\ASN1\Types\BaseType;
use phpseclib3\File\ASN1\Types\BitString;
use phpseclib3\File\ASN1\Types\Choice;
use phpseclib3\File\ASN1\Types\Integer;
use phpseclib3\File\ASN1\Types\OctetString;

/**
 * ASN.1 Constructed Array Object
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class Constructed implements \ArrayAccess, \Countable, \Iterator, BaseType
{
    private ?array $mapping = null;
    public ?array $decoded = null;
    public Choice|Constructed|null $parent = null;
    public int $depth = 0;
    public int|string $key;
    private array $rules = [];
    private string $wrapping = '';
    private bool $forcedCache = false;

    public function __construct(
        private string $encoded,
        private int $class,
        private int $tag,
        private int $start,
        private int $encoded_pos,
        private int $headerlength,
        private string $rawheader
    ) {
    }

    // you'd want to do this if you have a non-universal tag.
    // like to identify if it's present in a SEQUENCE you need the original tag
    // but to decode it you need the tag in the mapping
    public function replaceTag(int $tag): void
    {
        $this->tag = $tag;
    }

    public function getTag(): int
    {
        return $this->tag;
    }

    public function linkMapping(array $mapping, array $rules = []): void
    {
        $this->mapping = $mapping;
        $this->rules = $rules;
    }

    public function offsetExists(mixed $offset): bool
    {
        // `__isset()` is for stuff like $r->offset whereas `offsetExists()` is for stuff like $r['offset']
        self::decodeCurrent();

        return isset($this->decoded[$offset]);
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

    private function calculateIndefiniteLength(int &$offset, int $depth = 1): int
    {
        $origOffset = $offset;
        while (true) {
            ['tag' => $tag] = ASN1::decodeTag($this->encoded, $offset);
            $length = ASN1::decodeLength($this->encoded, $offset);
            if ($tag === 0 && $length === 0) {
                break;
            }
            if (!isset($length)) {
                $this->calculateIndefiniteLength($offset, $depth + 1);
            } else {
                $offset+= $length;
            }
        }

        return $offset - $origOffset;
    }

    public function &offsetGet(mixed $offset): mixed
    {
        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran; if you want to get the array keys do ->toArray()');
        }

        self::decodeCurrent();

        if (!isset($this->decoded[$offset])) {
            //throw new RuntimeException("The requested offset '$offset' was not found");
            $this->decoded[$offset] = [];
        }

        if ($this->decoded[$offset] instanceof Constructed) {
            try {
                $this->decoded[$offset]->decodeCurrent();
            } catch (\Exception $e) {
                if (ASN1::isBlobsOnBadDecodesEnabled()) {
                    $temp = new MalformedData($this->decoded[$offset]->encoded);
                    return $temp;
                }
                throw $e;
            }
        }

        return $this->decoded[$offset];
    }

    public function count(): int
    {
        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran; if you want to get the array keys do ->toArray()');
        }

        self::decodeCurrent();

        return count($this->decoded);
    }

    // $this->depth is normally set in either setSeqOuterLoop() or setSeqInnerLoop(), however,
    // constructed OCTET_STRINGs and BIT_STRINGs keep track of the depth via the $depth parameter
    // to decodeCurrent()
    private function decodeCurrent(?int $depth = null): void
    {
        if (isset($this->decoded)) {
            return;
        }

        $mapping = $this->mapping;
        $rules = $this->rules;

        $offset = 0;
        $decoded = [];

        if ($this->tag != $mapping['type']) {
            throw new RuntimeException('Found ' . ASN1::convertTypeConstantToString($this->tag) . ' - expecting ' . ASN1::convertTypeConstantToString($mapping['type']));
        }

        $content_len = strlen($this->encoded);
        while ($offset < $content_len) {
            try {
                $temp = ASN1::decodeBER($this->encoded, $this->start + $offset, $offset);
                $offset += $temp['headerlength'];

                $length = $temp['length'] ?? $this->calculateIndefiniteLength($offset);
                if (isset($temp['length'])) {
                    $offset += $length;
                } else {
                    $temp['actuallength'] = $length;
                }
                $decoded[] = $temp;
            } catch (EOCException $e) {
                break;
            }
        }

        switch ($this->tag) {
            // implicit time tags should never be explicit but sometimes they none-the-less are.
            // the following URLs elaborate
            // https://github.com/phpseclib/phpseclib/commit/511f55de3d1d504e4686f9d558a3c10709b413f8
            // https://github.com/phpseclib/phpseclib/issues/1388
            case ASN1::TYPE_GENERALIZED_TIME:
            case ASN1::TYPE_UTC_TIME:
                $this->parent->decoded[$this->key] = ASN1::map($decoded[0], $mapping);
                $this->decoded = [];
                break;
            case ASN1::TYPE_BIT_STRING:
            case ASN1::TYPE_OCTET_STRING:
                $result = '';
                $excessivelyDeepData = false;
                foreach ($decoded as $content) {
                    if ($content['content'] instanceof Constructed) {
                        $temp = ASN1::map($content, [
                            'type' => ASN1::TYPE_CHOICE,
                            'children' => [
                                'data' => ['type' => $this->tag]
                            ]
                        ]);
                        $temp->key = 0;
                        $temp['data']->depth = $depth ?? $this->depth;
                        try {
                            self::incrementDepth($temp['data']->depth);
                            $temp['data']->decodeCurrent($temp['data']->depth);
                        } catch (ExcessivelyDeepDataException $e) {
                            if (!ASN1::isBlobsOnBadDecodesEnabled() || isset($depth)) {
                                throw $e;
                            }
                            $excessivelyDeepData = true;
                        }
                        $result.= $temp['data'];
                        continue;
                    }
                    if ($content['type'] != $this->tag) {
                        $error = 'All subtags of a constructed string should be the same type as the constructed string itself';
                        $error = "$error (found " . ASN1::convertTypeConstantToString($content['type']) . '; expected '. ASN1::convertTypeConstantToString($this->tag) . ')';
                        throw new RuntimeException($error);
                    }
                    $result.= $content['content'];
                }
                if ($excessivelyDeepData) {
                    $value = new ExcessivelyDeepData($this->rawheader . $result);
                } elseif ($this->tag == ASN1::TYPE_BIT_STRING) {
                    $value = new BitString($result);
                } else {
                    $value = new OctetString($result);
                }
                if ($this->parent instanceof Constructed) {
                    $this->parent->decoded[$this->key] = $value;
                } else {
                    $this->parent['data'] = $value;
                }
                $this->decoded = [];
                break;
            case ASN1::TYPE_SEQUENCE:
                $children = $mapping['children'];

                if (isset($mapping['min']) && isset($mapping['max'])) {
                    $this->decoded = $this->setSeqOuterLoop($decoded, $children);
                    break;
                }

                $map = [];
                $keys = array_keys($children);
                $j = 0;

                for ($i = 0; $i < count($decoded); $i++) {
                    $temp = $decoded[$i];
                    $tempClass = ASN1::CLASS_UNIVERSAL;
                    if (isset($temp['constant'])) {
                        $tempClass = $temp['type'];
                    }

                    while ($j < count($keys)) {
                        $key = $keys[$j++];
                        $child = $children[$key];
                        $candidate = $this->setSeqInnerLoop($child, $temp, $tempClass, $key);

                        if ($candidate) {
                            // Got the match: use it.
                            $map[$key] = $candidate;
                            if (isset($rules[$key]) && !$map[$key] instanceof MalformedData && !$map[$key] instanceof ExcessivelyDeepData) {
                                if (!is_callable($rules[$key])) {
                                    $map[$key]->rules = $rules[$key];
                                } else {
                                    $rules[$key]($map[$key]);
                                    $this->rules = [];
                                }
                            }
                            break;
                        } elseif (isset($child['default'])) {
                            if ($child['type'] == ASN1::TYPE_INTEGER && isset($child['mapping'])) {
                                $map[$key] = new Integer(array_search($child['default'], $child['mapping']));
                                $map[$key]->mappedValue = $child['default'];
                            } else {
                                $map[$key] = $child['default'];
                            }
                            if (isset($rules[$key])) {
                                $map[$key]->rules = $rules[$key];
                            }
                        } elseif (!isset($child['optional'])) {
                            if (ASN1::isBlobsOnBadDecodesEnabled()) {
                                $map[$key] = new MalformedData($temp['content']);
                                break;
                            }
                            throw new RuntimeException("Unable to find a matching element for $key in the SEQUENCE");
                        }
                    }
                }

                // after we've found all the $decoded elements that match we need to look to see if any that should have been
                // included are missing and if so then if those missing ones are optional
                while ($j < count($keys)) {
                    $key = $keys[$j++];
                    $child = $children[$key];
                    if (isset($child['default'])) {
                        $map[$key] = $child['type'] == ASN1::TYPE_INTEGER ? new Integer($child['default']) : $child['default'];
                        if (isset($rules[$key])) {
                            $map[$key]->rules = $rules[$key];
                        }
                    } elseif (!isset($child['optional'])) {
                        if (ASN1::isBlobsOnBadDecodesEnabled()) {
                            break;
                        }
                        throw new RuntimeException("Unable to find a matching element for $key in the SEQUENCE");
                    }
                }

                if ($j < count($decoded)) {
                    throw new RuntimeException('There were ' . count($decoded) . ' elements found in the decoded data but we\'re only expecting ' . count($keys) . ' (' . implode(', ', array_keys($map)) . ')');
                }

                $this->decoded = $map;
                break;
            // the main diff between sets and sequences is that in a sequence the elements must appear in a specific order whereas
            // in a set they can appear in any order
            case ASN1::TYPE_SET:
                $children = $mapping['children'];

                if (isset($mapping['min']) && isset($mapping['max'])) {
                    $this->decoded = $this->setSeqOuterLoop($decoded, $children);
                    break;
                }

                $map = [];

                for ($i = 0; $i < count($decoded); $i++) {
                    $temp = $decoded[$i];
                    $tempClass = ASN1::CLASS_UNIVERSAL;
                    if (isset($temp['constant'])) {
                        $tempClass = $temp['type'];
                    }

                    foreach ($mapping['children'] as $key => $child) {
                        if (isset($map[$key])) {
                            continue;
                        }

                        $candidate = $this->setSeqInnerLoop($child, $temp, $tempClass, $key);
                        if (!$candidate) {
                            continue;
                        }

                        // Got the match: use it.
                        $map[$key] = $candidate;
                        if (isset($rules[$key])) {
                            $map[$key]->rules = $rules[$key];
                        }
                        break;
                    }
                }

                foreach ($mapping['children'] as $key => $child) {
                    if (!isset($map[$key])) {
                        if (isset($child['default'])) {
                            $map[$key] = $child['type'] == ASN1::TYPE_INTEGER ? new Integer($child['default']) : $child['default'];
                            if (isset($rules[$key])) {
                                $map[$key]->rules = $rules[$key];
                            }
                        } elseif (!isset($child['optional'])) {
                            if (ASN1::isBlobsOnBadDecodesEnabled()) {
                                $map[$key] = new MalformedData($temp['content']);
                                break;
                            }
                            throw new RuntimeException("Unable to find a matching element for $key in the SET");
                        }
                    }
                }

                $this->decoded = $map;
                $this->rules = $rules;
                break;
            default:
                throw new RuntimeException('Unable to decode element (' . $this->tag . ') @ ' . $this->start);
        }
    }

    private function setSeqOuterLoop(array $decoded, array $children): array
    {
        $rules = $this->rules;
        $map = [];

        foreach ($decoded as $key=>$content) {
            try {
                $temp = ASN1::map($content, $children, $rules);
                if ($temp instanceof Constructed || $temp instanceof Choice) {
                    $temp->depth = $this->depth;
                    self::incrementDepth($temp->depth);
                    $temp->parent = $this;
                    $temp->key = $key;
                    if (isset($rules['*'])) {
                        if (!is_callable($rules['*'])) {
                            $temp->rules = $rules['*'];
                        } else {
                            $rules['*']($temp);
                            $this->rules = [];
                        }
                    }
                }
                $map[] = $temp;
            } catch (EncodedDataUnavailableException|ExcessivelyDeepDataException $e) {
                $data = substr($this->encoded, $content['start'] - $this->start, ($content['length'] ?? $content['actuallength']) + $content['headerlength']);
                $map[] = $e instanceof EncodedDataUnavailableException ? new Element($data) : new ExcessivelyDeepData($data);
            }
        }

        return $map;
    }

    private function setSeqInnerLoop(array $child, array $temp, int $tempClass, string $key): BaseType|Element|null
    {
        $rules = isset($this->rules[$key]) && is_array($this->rules[$key]) ? $this->rules[$key] : [];

        $maymatch = true;
        if ($child['type'] != ASN1::TYPE_CHOICE) {
            $childClass = ASN1::CLASS_UNIVERSAL;
            $constant = null;
            if (isset($child['class'])) {
                $childClass = $child['class'];
                $constant = $child['cast'];
            } elseif (isset($child['constant'])) {
                $childClass = ASN1::CLASS_CONTEXT_SPECIFIC;
                $constant = $child['constant'];
            }
            if (isset($constant) && isset($temp['constant'])) {
                // Can only match if constants and class match.
                $maymatch = $constant == $temp['constant'] && $childClass == $tempClass;
            } else {
                // Can only match if no constant expected and type matches or is generic.
                $maymatch = !isset($child['constant']) && array_search($child['type'], [$temp['type'], ASN1::TYPE_ANY, ASN1::TYPE_CHOICE]) !== false;
            }
        }

        if ($maymatch) {
            // Attempt submapping.
            try {
                $candidate = ASN1::map($temp, $child, $rules);
                if ($candidate instanceof Constructed || $candidate instanceof Choice) {
                    $candidate->depth = $this->depth;
                    self::incrementDepth($candidate->depth);
                    $candidate->parent = $this;
                    $candidate->key = $key;
                }
            // altho the data is unavailable to ASN1 it _is_ available to Constructed
            } catch (EncodedDataUnavailableException|ExcessivelyDeepDataException $e) {
                $data = substr($this->encoded, $temp['start'] - $this->start, ($temp['length'] ?? $temp['actuallength']) + $temp['headerlength']);
                return $e instanceof EncodedDataUnavailableException ? new Element($data) : new ExcessivelyDeepData($data);
            } catch (RuntimeException $e) {
                $maymatch = false;
            }
        }

        return $maymatch ? $candidate : null;
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

    public function offsetSet(mixed $offset, mixed $value): void
    {
        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran');
        }

        self::decodeCurrent();

        if (!isset($offset)) {
            // from <https://www.php.net/manual/en/language.types.array.php>:
            // "if no key is specified, the maximum of the existing int indices is taken,
            //  and the new key will be that maximum value plus 1 (but at least 0)"
            $keys = $this->keys();
            $max = count($keys) ? max($keys) : false;
            $offset = is_int($max) ? $max + 1 : 0;
            // also from the above URL:
            // "Note that the maximum integer key used for this need not currently exist in the array.
            //  It need only have existed in the array at some time since the last time the array was re-indexed."
            // (this functionality is not emulated and i've no intention to do so)
        }

        $this->decoded[$offset] = $value;

        if (ASN1::invalidateCache()) {
            $this->invalidateCache();
        }
    }

    public function offsetUnset(mixed $offset): void
    {
        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran');
        }

        self::decodeCurrent();

        unset($this->decoded[$offset]);

        $this->invalidateCache();
    }

    public function firstKey(): mixed
    {
        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran');
        }

        self::decodeCurrent();

        return array_key_first($this->decoded);
    }

    public function lastKey(): mixed
    {
        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran');
        }

        self::decodeCurrent();

        return array_key_last($this->decoded);
    }

    public function rekey(): void
    {
        // this is mainly intended to turn a sparse numerically indexed array into a dense array

        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran');
        }

        // no point in messing with $this->decoded if it hasn't been messed with
        if (!$this->decoded) {
            return;
        }

        $this->decoded = array_values($this->decoded);
    }

    public function __debugInfo(): array
    {
        if (!isset($this->mapping)) {
            // by default __debugInfo is recursive so if we want this to show the full
            // array all we gotta do is do "return $this->decoded;"
            $temp = [
                'encoded' => '...',
                'class' => $this->class,
                'tag' => $this->tag,
                'start' => $this->start,
                'encoded_pos' => $this->encoded_pos,
                'headerlength' => $this->headerlength
            ];
            return $temp;
        }

        self::decodeCurrent();

        foreach ($this->decoded as $key=>$value) {
            if ($value instanceof Constructed && !isset($value->decoded)) {
                // if we rely on __debugInfo's built-in recursiveness then we wouldn't be able to
                // replace Constructed objects with OctetString or BitString objects
                try {
                    $value->__debugInfo();
                } catch (\Exception $e) {
                    if (ASN1::isBlobsOnBadDecodesEnabled()) {
                        $this->decoded[$key] = new MalformedData($value->encoded);
                    } else {
                        throw $e;
                    }
                }
            }
            // ideally for an X509 cert, unless __debugInfo were called _directly_ on it, we'd
            // render the X509 cert differently. eg. as the PEM vs the broken down PEM
            //if ($value instanceof X509) {
            //    $this->decoded[$key] = "$value";
            //}
        }

        return $this->decoded;
    }

    public function hasTypeID(): bool
    {
        return false;
    }

    public function setWrapping(string $wrapping): void
    {
        $this->wrapping = $wrapping;
    }

    public function hasWrapping(): bool
    {
        return strlen($this->wrapping) !== 0;
    }

    public function getEncodedWithWrapping(): string
    {
        return $this->wrapping . $this->rawheader . $this->encoded;
    }

    public function hasEncoded(): bool
    {
        return strlen($this->rawheader) !== 0;
    }

    public function getEncoded(): string
    {
        return $this->rawheader . $this->encoded;
    }

    public function getEncodedLength(): int
    {
        return strlen($this->rawheader) + strlen($this->encoded);
    }

    public function setEncoded(string $header, string $encoded): void
    {
        $this->rawheader = $header;
        $this->encoded = $encoded;
    }

    public function getEncodedWithoutHeader(): string
    {
        return $this->encoded;
    }

    public function keys(): ?array
    {
        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran; if you want to get the array keys do ->toArray()');
        }

        self::decodeCurrent();

        return array_keys($this->decoded);
    }

    public function rewind(): void
    {
        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran; if you want to get the array keys do ->toArray()');
        }

        self::decodeCurrent();

        reset($this->decoded);
    }

    public function current(): mixed
    {
        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran; if you want to get the array keys do ->toArray()');
        }

        self::decodeCurrent();

        return current($this->decoded);
    }

    public function key(): mixed
    {
        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran; if you want to get the array keys do ->toArray()');
        }

        self::decodeCurrent();

        return key($this->decoded);
    }

    public function next(): void
    {
        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran; if you want to get the array keys do ->toArray()');
        }

        self::decodeCurrent();

        next($this->decoded);
    }

    public function valid(): bool
    {
        if (!$this->mapping) {
            throw new RuntimeException('map() has not been ran; if you want to get the array keys do ->toArray()');
        }

        self::decodeCurrent();

        return isset($this->decoded[key($this->decoded)]);
    }

    public function hasMapping(): bool
    {
        return isset($this->mapping);
    }

    public function currentlyDecoded(): array|string
    {
        if (!$this->decoded) {
            return '...';
        }

        $output = [];
        foreach ($this->decoded as $key=>$value) {
            if ($value instanceof Constructed) {
                $output[$key] = $value->decoded ? $value->currentlyDecoded() : '...';
            } else {
                $output[$key] = $value;
            }
        }
        return $output;
    }

    public function toArray(): array
    {
        if (!isset($this->mapping)) {
            throw new InsufficientSetupException('Cannot convert Constructed object to an array when no mapping has been provided');
        }

        self::decodeCurrent();
        $result = [];
        foreach ($this->decoded as $key=>$value) {
            try {
                if ($value instanceof Constructed || $value instanceof Choice) {
                    $value = $value->toArray();
                }
                $result[$key] = $value;
            } catch (\Exception $e) {
                if (ASN1::isBlobsOnBadDecodesEnabled()) {
                    $result[$key] = new MalformedData($value->encoded);
                    continue;
                }
                throw $e;
            }
        }

        return $result;
    }

    public function __toString(): string
    {
        if (!$this->hasEncoded()) {
            throw new RuntimeException('Unable to convert constructed to string');
        }
        return $this->getEncoded();
    }

    private static function incrementDepth(int &$depth): void
    {
        $depth++;
        if ($depth == ASN1::getRecursionDepth()) {
            throw new ExcessivelyDeepDataException("Depth exceeds safe limits ($depth)");
        }
    }
}
