<?php

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Crypt\EC;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\EC\Curves\Ed448;
use phpseclib3\Crypt\EC\Formats\Keys\Common;
use phpseclib3\Exception\LengthException;
use phpseclib3\Exception\UnexpectedValueException;

class Ed448PublicKey
{
    use Common;

    public static function load($key, #[SensitiveParameter] ?string $password = null): array
    {
        if (!Strings::is_stringable($key)) {
            throw new UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        if (strlen($key) != 57) {
            throw new LengthException('Key length should be 57 bytes');
        }

        $components = ['curve' => new Ed448()];
        $components['QA'] = self::extractPoint($key, $components['curve']);

        return $components;
    }
}
