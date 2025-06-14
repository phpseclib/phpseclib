<?php

declare(strict_types=1);

namespace phpseclib3\Crypt\DILITHIUM;

use phpseclib3\Crypt\DILITHIUM;
use phpseclib3\Crypt\Common;
use phpseclib3\Exception\RuntimeException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\PrivateKeyInfo;

final class PrivateKey extends DILITHIUM implements Common\PrivateKey
{
    use Common\Traits\PasswordProtected;

    public function sign($message)
    {
        if (self::$engines["PQC-OpenSSL"] && !empty($this->pem)) {
            if (openssl_sign($message, $signature, $this->pem, $this->hash->getHash())) {
                return $signature;
            } else {
                throw new RuntimeException("openssl_sign failed: " . openssl_error_string());
            }
        } else if (self::$engines['oqsphp'] && !empty($this->raw_bit_string)) {
            $signature = '';
            $oqs_signature = new OQS_SIGNATURE($this->method_name);

            if (OQS_SUCCESS === $oqs_signature->sign($signature, $this->hash->hash($message), $this->raw_bit_string)) {
                return $signature;
            } else {
                throw new RuntimeException("OQS_SIGNATURE->sign failed");
            }
        } else {
            throw new RuntimeException("No engine available");
        }
    }

    public function getPublicKey(): string
    {
        if (self::$engines["PQC-OpenSSL"]  && !empty($this->pem)) {
            $private_key = openssl_pkey_get_private($this->pem);
            $private_key_details = openssl_pkey_get_details($private_key);

            return $private_key_details['key'];
        } else if (self::$engines['oqsphp'] && !empty($this->pem)) {
            $extractedBER = ASN1::extractBER($this->pem);
            $decodedBER = ASN1::decodeBER($extractedBER);
            $private_key_raw = ASN1::asn1map($decodedBER[0], PrivateKeyInfo::MAP)['privateKey'];

            $sig = new OQS_SIGNATURE($this->method_name);
            $public_key_length = $sig->length_public_key;
            $private_key_length = $sig->length_private_key;

            // PQC-OpenSSL encodes privates keys as 0x04 or 0x03 || length || private_key || public_key
            // We need to extract public_key only
            if (strlen($private_key_raw) >= ($private_key_length + $public_key_length)) {
                $bytearray = unpack('c*', $private_key_raw);

                $offset = $private_key_length;
                // if it still has ASN1 type and length
                if ($bytearray[1] == 0x04 || $bytearray[1] == 0x03) {
                    // 0x80 indicates that second byte encodes number of bytes containing length
                    $len_bytes = ($bytearray[2] & 0x80) == 0x80 ? 1 + ($bytearray[2] & 0x7f) : 1;
                    // 1 is for type 0x04 or 0x03, rest is length_bytes
                    $offset = 1 + $len_bytes + $private_key_length;
                }
                return pack('c*', ...array_slice($bytearray, $offset, $public_key_length));
            } else {
                throw new RuntimeException("Could not extract public key from private key");
            }
        } else {
            throw new RuntimeException("No engine available");
        }
    }

    public function toString(string $type, array $options = []): string
    {
        if ((self::$engines["PQC-OpenSSL"] && self::$engines['oqsphp']) && !empty($this->pem)) {
            return $this->pem;
        } else {
            throw new RuntimeException("No data available");
        }
    }
}
