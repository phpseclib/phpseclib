<?php

declare(strict_types=1);

namespace phpseclib3\Crypt\DILITHIUM\Formats\Keys;

use OQS_SIGNATURE;
use phpseclib3\Exception\UnexpectedValueException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\PrivateKeyInfo;
use phpseclib3\File\ASN1\Maps\PublicKeyInfo;

abstract class PEM
{
    public static function load($array, ?string $password = null): array
    {
        $key_pem = $array['key_pem'];
        $method_name = $array['method_name'];

        $components = [
            'isPublicKey' => str_contains($key_pem, 'PUBLIC'),
            'isPrivateKey' => str_contains($key_pem, 'PRIVATE'),
            'method_name' => $method_name,
        ];

        if (!$components['isPublicKey'] && !$components['isPrivateKey']) {
            throw new UnexpectedValueException('Key should be a PEM formatted string');
        }

        $components['pem'] = $key_pem;

        // extract raw key
        $extractedBER = ASN1::extractBER($key_pem);
        $decodedBER = ASN1::decodeBER($extractedBER);

        if ($components['isPrivateKey']) {
            $raw_key = ASN1::asn1map($decodedBER[0], PrivateKeyInfo::MAP)['privateKey'];
            $sig = new OQS_SIGNATURE($method_name);
            $max_length = $sig->length_private_key;

            // PQC-OpenSSL encodes privates keys as 0x04 or 0x03 || length || private_key || public_key
            // We need to extract private_key only
            if (strlen($raw_key) > $max_length) {
                $bytearray = unpack('c*', $raw_key);

                $offset = 0;
                // if it still has ASN1 type and length
                if ($bytearray[1] == 0x04 || $bytearray[1] == 0x03) {
                    // 0x80 indicates that second byte encodes number of bytes containing length
                    $len_bytes = ($bytearray[2] & 0x80) == 0x80 ? 1 + ($bytearray[2] & 0x7f) : 1;
                    // 1 is for type 0x04 or 0x03, rest is length_bytes
                    $offset = 1 + $len_bytes;
                }
                $private_key_raw = pack('c*', ...array_slice($bytearray, $offset, $max_length));
            }
            $components['raw'] = $private_key_raw;
        } else if ($components['isPublicKey']) {
            $raw_key = ASN1::asn1map($decodedBER[0], PublicKeyInfo::MAP)['publicKey'];

            // Check if first byte in string is 0
            // If it is, it means that the public key is encoded as a positive integer and we need to remove first byte in order to extract the public key
            // If it is not, it means that the public key is encoded as a bit string - TODO: fact check this
            if (unpack('c', $raw_key)[1] === 0) {
                // Remove first byte from bit string
                $raw_key = pack('c*', ...array_slice(unpack('c*', $raw_key), 1));
            }
            $components['raw'] = $raw_key;
        }

        return $components;
    }
}
