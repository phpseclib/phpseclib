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

use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\ASN1\Types\Choice;
use phpseclib4\File\CMS\EnvelopedData;

class PasswordRecipient extends Recipient implements DerivableKey, SearchableKey
{
    private ?string $password = null;

    protected static function loadString(string $encoded): Constructed
    {
        //ASN1::disableCacheInvalidation();
        $rules = [];
        $rules['keyEncryptionAlgorithm'] = $rules['keyDerivationAlgorithm'] = [self::class, 'mapInAlgoParams'];
        $decoded = ASN1::decodeBER($encoded);
        $recipient = ASN1::map($decoded, Maps\PasswordRecipientInfo::MAP, $rules);
        //ASN1::enableCacheInvalidation();
        return $recipient;
    }

    public static function mapInAlgoParams(Constructed $algorithm): void
    {
        $temp = ASN1::decodeBER($algorithm['parameters']->getEncoded());
        $temp = match ((string) $algorithm['algorithm']) {
            'id-alg-PWRI-KEK' => ASN1::map($temp, Maps\AlgorithmIdentifier::MAP),
            'id-PBKDF2' => ASN1::map($temp, Maps\PBKDF2params::MAP),
            default => null,
        };
        ASN1::disableCacheInvalidation();
        if (isset($temp)) {
            $algorithm['parameters'] = $temp;
        }
        ASN1::enableCacheInvalidation();
    }

    public function withPassword(#[\SensitiveParameter] string $password): self
    {
        if ($this->recipient['keyEncryptionAlgorithm']['algorithm'] != 'id-alg-PWRI-KEK') {
            throw new UnsupportedAlgorithmException(
                'id-alg-PWRI-KEK is the only supported keyEncryptionAlgorithm (' .
                $this->recipient['keyEncryptionAlgorithm']['algorithm'] . ' found)'
            );
        }

        // see https://datatracker.ietf.org/doc/html/rfc3211
        $keyCipher = self::getPBES2EncryptionObject((string) $this->recipient['keyEncryptionAlgorithm']['parameters']['algorithm']);
        $keyCipher->disablePadding();
        self::setupPBKDF2($this->recipient['keyDerivationAlgorithm'], $password, $keyCipher);

        $blockSize = $keyCipher->getBlockLengthInBytes();

        $encrypted = (string) $this->recipient['encryptedKey'];
        $keyCipher->setIV(substr($encrypted, 0, $blockSize));
        $result = $keyCipher->decrypt(substr($encrypted, $blockSize));
        $keyCipher->setIV(substr($result, -$keyCipher->getBlockLengthInBytes()));
        $result = $keyCipher->decrypt(substr($encrypted, 0, $blockSize)) . $result;
        $keyCipher->setIV((string) $this->recipient['keyEncryptionAlgorithm']['parameters']['parameters']);
        $result = $keyCipher->decrypt($result);

        $length = ord($result);
        $cek = substr($result, 4, $length);
        $keyCheck = ~substr($result, 1, 3);
        if (substr($cek, 0, 3) != $keyCheck) {
            throw new UnexpectedValueException('keyCheck failed');
        }

        //if (!$this->cms instanceof Constructed) {
        $this->cms->cek = $cek;
        //}

        return $this;
    }

    public function toString(): string
    {
        $recipient = ASN1::encodeDER($this->recipient, Maps\PasswordRecipientInfo::MAP);

        return $recipient;
    }
}