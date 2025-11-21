<?php

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\EC;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\EC\Curves\Ed448;
use phpseclib4\Exception\LengthException;
use phpseclib4\Exception\UnexpectedValueException;

class Ed448PrivateKey
{
    public static function load($key, #[SensitiveParameter] ?string $password = null): array
    {
        if (!Strings::is_stringable($key)) {
            throw new UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        if (strlen($key) != 57) {
            throw new LengthException('Key length should be 57 bytes');
        }

        $components = ['curve' => new Ed448()];
        $arr = $components['curve']->extractSecret($key);
        $components['dA'] = $arr['dA'];
        $components['secret'] = $arr['secret'];
        $components['QA'] = $components['curve']->multiplyPoint($components['curve']->getBasePoint(), $components['dA']);

        return $components;
    }
}
