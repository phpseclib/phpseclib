<?php

/**
 * Generic ASN.1 Type Helper functions
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
 * Generic ASN.1 Type Helper functions
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
trait Common
{
    public array $metadata = [];

    public function addMetadata(array $metadata): void
    {
        $this->metadata = $metadata;
    }

    public function enableForcedCache(): void
    {
        $this->metadata['forcedCache'] = true;
    }

    public function disableForcedCache(): void
    {
        unset($this->metadata['forcedCache']);
    }

    public function isCacheForced(): bool
    {
        return isset($this->metadata['forcedCache']) && $this->metadata['forcedCache'];
    }

    public function setWrapping(string $wrapping): void
    {
        $this->metadata['wrapping'] = $wrapping;
    }

    public function hasWrapping(): bool
    {
        return !empty($this->metadata['wrapping']);
    }

    public function getEncodedWithWrapping(): string
    {
        return ($this->metadata['wrapping'] ?? '') . $this->metadata['rawheader'] . $this->metadata['content'];
    }

    public function hasEncoded(): bool
    {
        return isset($this->metadata['content'], $this->metadata['rawheader']);
    }

    public function getEncoded(): string
    {
        if (!isset($this->metadata['content'], $this->metadata['rawheader'])) {
            throw new RuntimeException('Encoded data is not available');
        }
        return $this->metadata['rawheader'] . $this->metadata['content'];
    }

    public function getEncodedWithoutHeader(): string
    {
        if (!isset($this->metadata['content'])) {
            throw new RuntimeException('Encoded data is not available');
        }
        return $this->metadata['content'];
    }

    public function getEncodedLength(): int
    {
        if (!isset($this->metadata['content'], $this->metadata['rawheader'])) {
            throw new RuntimeException('Encoded data is not available');
        }
        return strlen($this->metadata['rawheader']) + strlen($this->metadata['content']);
    }

    public function setEncoded(string $header, string $encoded): void
    {
        $this->metadata['rawheader'] = $header;
        $this->metadata['content'] = $encoded;
    }

    // doesn't work on UTCTime or GeneralizedTime per https://github.com/php/php-src/issues/11310
    public function __debugInfo(): array
    {
        $temp = get_object_vars($this);
        unset($temp['metadata']);
        return $temp;
    }

    public function hasTypeID(): bool
    {
        try {
            $this->getTypeID();
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    public function getTypeID(): int
    {
        $reflection = new \ReflectionClassConstant(static::CLASS, 'TYPE');
        return $reflection->getValue();
    }
}
