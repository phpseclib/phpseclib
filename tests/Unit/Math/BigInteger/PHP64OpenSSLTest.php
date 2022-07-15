<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Math\BigInteger;

use phpseclib3\Exception\BadConfigurationException;
use phpseclib3\Math\BigInteger\Engines\PHP64;

class PHP64OpenSSLTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!PHP64::isValidEngine()) {
            self::markTestSkipped('64-bit integers are not available.');
        }

        try {
            PHP64::setModExpEngine('OpenSSL');
        } catch (BadConfigurationException $e) {
            self::markTestSkipped('openssl_public_encrypt() function is not available.');
        }
    }

    public function getInstance($x = 0, $base = 10): PHP64
    {
        return new PHP64($x, $base);
    }

    public function testInternalRepresentation(): void
    {
        $x = new PHP64('FFFFFFFFFFFFFFFFC90FDA', 16);
        $y = new PHP64("$x");

        $this->assertSame(self::getVar($x, 'value'), self::getVar($y, 'value'));
    }

    public static function getStaticClass(): string
    {
        return 'phpseclib3\Math\BigInteger\Engines\PHP64';
    }
}
