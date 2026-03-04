<?php
/**
 * Pure-PHP CMS / KEKRecipient Parser
 *
 * PHP version 8
 *
 * Encode and decode CMS / EnvelopedData / KEKRecipient files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\CMS\EnvelopedData;

use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps;

class KEKRecipient extends Recipient implements DerivableKey
{
    private ?string $kek = null;

    protected static function loadString(string $encoded): Constructed
    {
        //ASN1::disableCacheInvalidation();
        $decoded = ASN1::decodeBER($encoded);
        $recipient = ASN1::map($decoded, Maps\KEKRecipientInfo::MAP);
        //ASN1::enableCacheInvalidation();
        return $recipient;
    }

    public function withKey(#[\SensitiveParameter] string $key): self
    {
        $kek = $key;
        $encryptedKey = (string) $this->recipient['encryptedKey'];
        switch ($this->recipient['keyEncryptionAlgorithm']['algorithm']) {
            case 'id-aes128-wrap':
            case 'id-aes192-wrap':
            case 'id-aes256-wrap':
                // from https://datatracker.ietf.org/doc/html/rfc3394.html#section-2.2.3.1
                $iv = "\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6";
                $cek = self::unwrapAES($kek, $iv, $encryptedKey);
                break;
            case 'id-alg-CMS3DESwrap':
                $cek = self::unwrap3DES($kek, $encryptedKey);
                break;
            default:
                throw new UnsupportedAlgorithmException($this->recipient['keyEncryptionAlgorithm']['algorithm'] . ' is not a supported algorithm');
        }

        //if (!$this->cms instanceof Constructed) {
        $this->cms->cek = $cek;
        //}

        return $this;
    }

    public function toString(): string
    {
        $recipient = ASN1::encodeDER($this->recipient, Maps\KEKRecipientInfo::MAP);

        return $recipient;
    }
}