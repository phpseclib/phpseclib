<?php

declare(strict_types=1);

namespace phpseclib3\Crypt\DILITHIUM;

use phpseclib3\Crypt\Common;
use phpseclib3\Crypt\DILITHIUM;
use phpseclib3\Exception\RuntimeException;

final class PublicKey extends DILITHIUM implements Common\PublicKey
{
    use Common\Traits\Fingerprint;

    public function verify($message, $signature)
    {
        if (self::$engines["PQC-OpenSSL"] && !empty($this->pem)) {
            $result = openssl_verify($message, $signature, $this->pem, $this->hash->getHash());
            if ($result === false) {
                throw new RuntimeException("openssl_verify failed: " . openssl_error_string());
            } else {
                return boolval($result);
            }
        } else if (self::$engines['oqsphp'] && !empty($this->raw_bit_string)) {
            $oqs_signature = new \OQS_SIGNATURE($this->method_name);

            return \OQS_SUCCESS === $oqs_signature->verify($this->hash->hash($message), $signature, $this->raw_bit_string);
        } else {
            throw new RuntimeException("No engine available");
        }
    }

    public function toString(string $type, array $options = []): string
    {
        if ((self::$engines["PQC-OpenSSL"] || self::$engines['oqsphp']) && !empty($this->pem)) {
            return $this->pem;
        } else {
            throw new RuntimeException("No data available");
        }
    }
}
