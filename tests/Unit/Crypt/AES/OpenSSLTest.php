<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014-2026 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\AES;

use phpseclib4\Crypt\AES;

class OpenSSLTest extends TestCase
{
    protected function setUp(): void
    {
        $this->engine = 'OpenSSL';
    }

    public static function continuousBufferCombos(): array
    {
        return self::withoutOFB8(parent::continuousBufferCombos());
    }

    public static function continuousBufferBatteryCombos(): array
    {
        return self::withoutOFB8(parent::continuousBufferBatteryCombos());
    }

    public static function continuousBufferBatteryCombosWithoutSingleCombos(): array
    {
        return self::withoutOFB8(parent::continuousBufferBatteryCombosWithoutSingleCombos());
    }

    /**
     * OpenSSL has no OFB8 mode, so these combos could only ever be skipped.
     */
    private static function withoutOFB8(array $combos): array
    {
        return array_filter($combos, fn (array $combo) => !in_array('ofb8', $combo, true));
    }

    public function testOFBUsesOpenSSLOFBMode(): void
    {
        $mode = self::callFunc(new AES('ofb'), 'openssl_translate_mode');

        $this->assertSame('ofb', $mode);
    }
}
