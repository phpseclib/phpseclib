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
            throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        $components = ['curve' => new Ed448()];
        $components['dA'] = $components['curve']->extractSecret($key);
        $components['QA'] = $components['curve']->multiplyPoint($components['curve']->getBasePoint(), $components['dA']);

        return $components;
    }
}
