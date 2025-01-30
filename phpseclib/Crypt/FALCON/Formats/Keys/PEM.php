<?php

declare(strict_types=1);

namespace phpseclib3\Crypt\FALCON\Formats\Keys;

use phpseclib3\Exception\UnexpectedValueException;

abstract class PEM
{
    public static function load($key, ?string $password = null): array
    {
        $components = [
            'isPublicKey' => str_contains($key, 'PUBLIC'),
            'isPrivateKey' => str_contains($key, 'PRIVATE')
        ];

        if (!isset($components['isPublicKey']) && !isset($components['isPrivateKey'])) {
            throw new UnexpectedValueException('Key should be a PEM formatted string');
        }

        $components['pem'] = $key;

        return $components;
    }
}
