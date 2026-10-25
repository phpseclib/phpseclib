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

    public function testOFBUsesOpenSSLOFBMode(): void
    {
        $mode = self::callFunc(new AES('ofb'), 'openssl_translate_mode');

        $this->assertSame('ofb', $mode);
    }
}
