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

namespace phpseclib4\File\Common\Traits;

use phpseclib4\Exception\InsufficientSetupException;
use phpseclib4\Exception\LengthException;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\CMS\EncryptedData;
use phpseclib4\Crypt\AES;
use phpseclib4\Crypt\TripleDES;

trait KeyDerivation
{
    use \phpseclib4\Crypt\Common\Traits\ASN1AlgorithmIdentifier;

    // used by both KEKRecipient and KeyAgreeRecipient
    protected static function unwrapAES(#[\SensitiveParameter] string $key, #[\SensitiveParameter] string $iv, string $ciphertext): string
    {
        $c = str_split($ciphertext, 8);
        $n = count($c) - 1;

        $aes = new AES('ecb');
        $aes->setKey($key);
        $aes->disablePadding();

        // 1) Initialize variables.
        $r = $c;
        $a = array_shift($r);

        // 2) Compute intermediate values.
        for ($j = 5; $j >= 0; $j--) {
            for ($i = $n - 1; $i >= 0; $i--) {
                $t = pack('J', $n * $j + $i + 1);
                $b = $aes->decrypt(($a ^ $t) . $r[$i]);
                $a = substr($b, 0, 8);
                $r[$i] = substr($b, 8);
            }
        }

        if ($a != $iv) {
            throw new RuntimeException('Error with unwrapping');
        }
        return implode('', $r);
    }

    // used by both KEKRecipient and KeyAgreeRecipient
    // from https://www.rfc-editor.org/rfc/rfc3217#section-3.2
    protected static function unwrap3DES(#[\SensitiveParameter] string $kek, #[\SensitiveParameter] string $wrapped): string
    {
        if (strlen($wrapped) != 40) {
            throw new LengthException('Wrapped key should be 40 octets in length');
        }
        $cipher = new TripleDES('cbc');
        $cipher->disablePadding();
        $cipher->setKey($kek);
        $cipher->setIV("\x4a\xdd\xa2\x2c\x79\xe8\x21\x05");
        $temp3 = $cipher->decrypt($wrapped);
        $temp2 = strrev($temp3);
        $iv = substr($temp2, 0, 8);
        $temp1 = substr($temp2, 8);
        //$cipher->setKey($kek);
        $cipher->setIV($iv);
        $cekicv = $cipher->decrypt($temp1);
        $cek = substr($cekicv, 0, 24);
        $icv = substr($cekicv, -8);
        if ($icv != substr(sha1($cek, true), 0, 8)) {
            throw new RuntimeException('Checksum validation failed');
        }
        return $cek;
    }

    public function decrypt(): string
    {
        if ($this instanceof EncryptedData) {
            $cek = &$this->cek;
            $cms = &$this;
        } else {
            $cek = &$this->cms->cek;
            $cms = &$this->cms;
        }
        if (!isset($cek)) {
            throw new InsufficientSetupException('Content encryption key not set');
        }

        $cea = ASN1::decodeBER((string) $cms['content']['encryptedContentInfo']['contentEncryptionAlgorithm']);
        $cea = ASN1::map($cea, ASN1\Maps\AlgorithmIdentifier::MAP);
        $contentCipher = self::getPBES2EncryptionObject((string) $cea['algorithm']);
        $contentCipher->setKey($cek);
        $contentCipher->setIV((string) $cea['parameters']);

        return $contentCipher->decrypt((string) $cms['content']['encryptedContentInfo']['encryptedContent']);
    }
}