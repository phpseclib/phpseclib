<?php

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Crypt\EC;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\EC\Curves\Ed448;
use phpseclib3\Crypt\EC\Formats\Keys\Common;

class Ed448PublicKey
{
    use Common;

    public static function load($key, ?string $password = null): array
    {
        if (!Strings::is_stringable($key)) {
            throw new \phpseclib3\Exception\UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        $components = ['curve' => new Ed448()];
        $components['QA'] = self::extractPoint($key, $components['curve']);

        return $components;
    }
}
