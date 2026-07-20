<?php

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\EC;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\EC\Curves\Ed448;
use phpseclib4\Crypt\EC\Formats\Keys\Common;
use phpseclib4\Exception\LengthException;
use phpseclib4\Exception\UnexpectedValueException;

class Ed448PublicKey
{
    use Common;

    /** @psalm-suppress PossiblyUnusedParam */
    public static function load(
        #[\SensitiveParameter] string $key,
        #[\SensitiveParameter] ?string $password = null
    ): array {
        if (strlen($key) != 57) {
            throw new LengthException('Key length should be 57 bytes');
        }

        $components = ['curve' => new Ed448()];
        $components['QA'] = self::extractPoint($key, $components['curve']);

        return $components;
    }
}
