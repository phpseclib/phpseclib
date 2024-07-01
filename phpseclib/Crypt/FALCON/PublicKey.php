<?php

declare(strict_types=1);

namespace phpseclib3\Crypt\FALCON;

use phpseclib3\Crypt\FALCON;
use phpseclib3\Crypt\Common;
use phpseclib3\Exception\RuntimeException;

final class PublicKey extends FALCON implements Common\PublicKey
{
    use Common\Traits\Fingerprint;

    public function verify($message, $signature)
    {
        $result = openssl_verify($message, $signature, $this->pem, $this->hash->getHash());
        if ($result === false) {
            throw new RuntimeException("openssl_verify failed: " . openssl_error_string());
        } else {
            return boolval($result);
        }
    }

    public function toString(string $type, array $options = []): string
    {
        return $this->pem;
    }
}
