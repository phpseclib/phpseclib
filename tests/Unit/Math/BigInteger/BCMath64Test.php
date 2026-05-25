<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013-2026 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Math\BigInteger;

use phpseclib4\Math\BigInteger\Engines\BCMath64;

class BCMath64Test extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!BCMath64::isValidEngine()) {
            self::markTestSkipped('BCMath64 extension is either not available or you\'re on a 32-bit PHP install');
        }
        BCMath64::setModExpEngine('DefaultEngine');
    }

    public function getInstance($x = 0, $base = 10): BCMath64
    {
        return new BCMath64($x, $base);
    }

    #[\PHPUnit\Framework\Attributes\Group('github2089')]
    public function testBCSscale(): void
    {
        bcscale(1);
        $number = new BCMath64('115792089210356248762697446949407573530086143415290314195533631308867097853951', 10);
        $this->assertTrue($number->isPrime());
        bcscale(0);
    }

    public static function getStaticClass(): string
    {
        return 'phpseclib4\Math\BigInteger\Engines\BCMath64';
    }
}
