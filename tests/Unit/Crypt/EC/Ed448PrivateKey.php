<?php

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Crypt\EC;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\EC\Curves\Ed448;

class Ed448PrivateKey
{
    public static function load($key, ?string $password = null): array
    {
        if (!Strings::is_stringable($key)) {
            throw new \phpseclib3\Exception\UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        $components = ['curve' => new Ed448()];
        $arr = $components['curve']->extractSecret($key);
        $components['dA'] = $arr['dA'];
        $components['secret'] = $arr['secret'];
        $components['QA'] = $components['curve']->multiplyPoint($components['curve']->getBasePoint(), $components['dA']);

        return $components;
    }
}
