<?php
/**
 * Pure-PHP CMS / KeyTransRecipient Parser
 *
 * PHP version 8
 *
 * Encode and decode CMS / EnvelopedData / KeyTransRecipient files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\CMS\EnvelopedData;

use phpseclib4\Common\Functions\Arrays;
use phpseclib4\Crypt\RSA;
use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\X509;

class KeyTransRecipient extends Recipient implements DerivableKey, SearchableKey
{
    private ?RSA\PrivateKey $kek = null;

    protected static function loadString(string $encoded): Constructed
    {
        //ASN1::disableCacheInvalidation();
        $decoded = ASN1::decodeBER($encoded);
        $rules = [];
        $rules['keyEncryptionAlgorithm'] = [self::class, 'mapInAlgoParams'];
        $recipient = ASN1::map($decoded, Maps\KeyTransRecipientInfo::MAP, $rules);
        //ASN1::enableCacheInvalidation();
        return $recipient;
    }

    public static function mapInAlgoParams(Constructed $algorithm): void
    {
        $temp = ASN1::decodeBER($algorithm['parameters']->getEncoded());
        $rules = [];
        switch ($algorithm['algorithm']) {
            case 'id-RSAES-OAEP':
                $rules['maskGenAlgorithm'] = [self::class, 'mapInAlgoParams'];
                $map = Maps\RSAES_OAEP_params::MAP;
                break;
            case 'id-mgf1':
                $map = Maps\MaskGenAlgorithm::MAP;
                break;
            default:
                return;
        }
        ASN1::disableCacheInvalidation();
        $algorithm['parameters'] = ASN1::map($temp, $map, $rules);
        ASN1::enableCacheInvalidation();
    }

    public function withKey(#[\SensitiveParameter] RSA\PrivateKey $key): self
    {
        $kek = &$key;

        $encryptedKey = (string) $this->recipient['encryptedKey'];
        if ($this->recipient['keyEncryptionAlgorithm']['algorithm'] == 'id-RSAES-OAEP') {
            $kek = $kek->withPadding(RSA::ENCRYPTION_OAEP);
            $algorithm = Arrays::subArray($this->recipient, 'keyEncryptionAlgorithm/parameters/hashAlgorithm')['algorithm'] ?? 'sha1';
            $kek = $kek->withHash(preg_replace('#^id-#', '', "$algorithm"));
            $algorithm = Arrays::subArray($this->recipient, 'keyEncryptionAlgorithm/parameters/maskGenAlgorithm')['algorithm'] ?? 'id-mgf1';
            if ($algorithm != 'id-mgf1') {
                throw new UnsupportedAlgorithmException("Unsupported maskGenAlgorithm ($algorithm) found - only id-mgf1 is supported");
            }
            $algorithm = Arrays::subArray($this->recipient, 'keyEncryptionAlgorithm/parameters/maskGenAlgorithm/parameters')['algorithm'] ?? 'sha1';
            $kek = $kek->withMGFHash(preg_replace('#^id-#', '', "$algorithm"));
            $algorithm = Arrays::subArray($this->recipient, 'keyEncryptionAlgorithm/parameters/pSourceAlgorithm')['algorithm'] ?? 'id-pSpecified';
            if ($algorithm != 'id-pSpecified') {
                throw new UnsupportedAlgorithmException("Unsupported maskGenAlgorithm ($algorithm) found - only id-mgf1 is supported");
            }
            $label = Arrays::subArray($this->recipient, 'keyEncryptionAlgorithm/parameters/pSourceAlgorithm')['parameters'] ?? '';
            $kek = $kek->withLabel("$label");
        }

        //if (!$this->cms instanceof Constructed) {
        $this->cms->cek = $kek->decrypt($encryptedKey);
        //}

        return $this;
    }

    public function matchesX509(X509 $x509): bool
    {
        return $x509->isIssuerOf($this->recipient['rid'], ['keyEncipherment']);
    }

    public function toString(): string
    {
        $recipient = ASN1::encodeDER($this->recipient, Maps\KeyTransRecipientInfo::MAP);

        return $recipient;
    }
}