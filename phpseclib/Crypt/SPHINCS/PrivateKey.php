<?php

declare(strict_types=1);

namespace phpseclib3\Crypt\SPHINCS;

use phpseclib3\Crypt\SPHINCS;
use phpseclib3\Crypt\Common;
use phpseclib3\Exception\RuntimeException;

final class PrivateKey extends SPHINCS implements Common\PrivateKey
{
    use Common\Traits\PasswordProtected;

    public function sign($message)
    {
        if ($result = openssl_sign($message, $signature, $this->pem, $this->hash->getHash())) {
            return $signature;
        } else {
            throw new RuntimeException("openssl_sign failed: " . openssl_error_string());
        }
    }

    public function getPublicKey(): string
    {
        $private_key = openssl_pkey_get_private($this->pem);
        $private_key_details = openssl_pkey_get_details($private_key);

        return $private_key_details['key'];
    }

    public function toString(string $type, array $options = []): string
    {
        return $this->pem;
    }
}
