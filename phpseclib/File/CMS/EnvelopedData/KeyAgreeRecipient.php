<?php
/**
 * Pure-PHP CMS / KeyAgreeRecipient Parser
 *
 * PHP version 8
 *
 * Encode and decode CMS / EnvelopedData / KeyAgreeRecipient files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\CMS\EnvelopedData;

use phpseclib4\Exception\InsufficientSetupException;
use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps;

class KeyAgreeRecipient extends Recipient
{
    protected static function loadString(string $encoded): Constructed
    {
        //ASN1::disableCacheInvalidation();
        $decoded = ASN1::decodeBER($encoded);
        $rules = [];
        $rules['keyEncryptionAlgorithm'] = [self::class, 'mapInAlgoParams'];
        $rules['recipientEncryptedKeys'] = [self::class, 'mapInEncryptedKeys'];
        $recipient = ASN1::map($decoded, Maps\KeyAgreeRecipientInfo::MAP, $rules);
        //ASN1::enableCacheInvalidation();
        return $recipient;
    }

    public static function mapInAlgoParams(Constructed $algorithm): void
    {
        ASN1::disableCacheInvalidation();
        $temp = ASN1::decodeBER($algorithm['parameters']->getEncoded());
        $algorithm['parameters'] = ASN1::map($temp, Maps\AlgorithmIdentifier::MAP);
        ASN1::enableCacheInvalidation();
    }

    public static function mapInEncryptedKeys(Constructed $keys): void
    {
        ASN1::disableCacheInvalidation();
        foreach ($keys as $i => $key) {
            $keys[$i] = new KeyAgreeRecipient\EncryptedKey($key);
            $keys[$i]->parent = $keys;
            $keys[$i]->key = $i;
            $keys[$i]->depth = $keys->depth + 1;
            //$keys[$i]->cms = $keys->cms;
            //$keys[$i]->recipient = $keys->recipient;
        }
        ASN1::enableCacheInvalidation();
    }

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

    public function getEncryptedKeys(): array
    {
        $result = [];
        foreach ($this->recipient['recipientEncryptedKeys'] as $key) {
            $result[] = $key;
        }
        return $result;
    }
}