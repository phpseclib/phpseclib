<?php

/**
 * Exercise the documented mode-translation extension point with real AES ECB.
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\AES;

use phpseclib4\Crypt\AES;

class OpenSSLModeCipher extends AES
{
    protected function openssl_translate_mode(): ?string
    {
        return match ($this->mode) {
            self::MODE_OFB8 => 'ecb', // The base OFB8 loop constructs the mode from ECB.
            self::MODE_CTR => 'unavailable', // Exercise the real ECB fallback without changing providers.
            default => parent::openssl_translate_mode(),
        };
    }
}
