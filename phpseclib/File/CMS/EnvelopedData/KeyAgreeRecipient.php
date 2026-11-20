<?php

/**
 * Pure-PHP CMS / KeyAgreeRecipient Parser
 *
 * PHP version 8.1+
 *
 * Encode and decode CMS / EnvelopedData / KeyAgreeRecipient files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\CMS\EnvelopedData;

use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\{Constructed, Maps};

class KeyAgreeRecipient extends Recipient
{
    /** @psalm-api */
    protected static function loadString(string $encoded): Constructed
    {
        //ASN1::disableCacheInvalidation();
        $decoded = ASN1::decodeBER($encoded);
        $rules = [];
        $rules['keyEncryptionAlgorithm'] = self::mapInAlgoParams(...);
        $rules['recipientEncryptedKeys'] = self::mapInEncryptedKeys(...);
        $recipient = ASN1::map($decoded, Maps\KeyAgreeRecipientInfo::MAP, $rules);
        //ASN1::enableCacheInvalidation();
        // @phpstan-ignore return.type (BI-026 remains open: blob recovery can return MalformedData; see BI-026-asn1-loadstring-blob-root-typeerrors.md.)
        return $recipient;
    }

    public static function mapInAlgoParams(Constructed $algorithm): void
    {
        if (!isset($algorithm['parameters'])) {
            return;
        }
        ASN1::disableCacheInvalidation();
        try {
            $temp = ASN1::decodeBER($algorithm['parameters']->getEncoded());
            $algorithm['parameters'] = ASN1::map($temp, Maps\AlgorithmIdentifier::MAP);
        } finally {
            ASN1::enableCacheInvalidation();
        }
    }

    public static function mapInEncryptedKeys(Constructed $keys): void
    {
        ASN1::disableCacheInvalidation();
        try {
            foreach ($keys as $i => $key) {
                $keys[$i] = new KeyAgreeRecipient\EncryptedKey($key);
                $keys[$i]->parent = $keys;
                $keys[$i]->key = $i;
                $keys[$i]->depth = $keys->depth + 1;
                //$keys[$i]->cms = $keys->cms;
                //$keys[$i]->recipient = $keys->recipient;
            }
        } finally {
            ASN1::enableCacheInvalidation();
        }
    }

    /** @psalm-api */
    public function toString(): string
    {
        $recipient = ASN1::encodeDER($this->recipient, Maps\KeyAgreeRecipientInfo::MAP);

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
        $temp = self::load("$this");
        foreach ($temp as $key => $val) {
            if ($key == 'recipientEncryptedKeys') {
                continue;
            }
            $this->recipient[$key] = $val;
        }
    }

    /** @psalm-api */
    public function getEncryptedKeys(): array
    {
        $result = [];
        foreach ($this->recipient['recipientEncryptedKeys'] as $key) {
            $result[] = $key;
        }
        return $result;
    }
}
