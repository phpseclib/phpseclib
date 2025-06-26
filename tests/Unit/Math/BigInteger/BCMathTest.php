<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Unit\Math\BigInteger;

use phpseclib3\Math\BigInteger\Engines\BCMath;

class BCMathTest extends TestCase
{
    public static function setUpBeforeClass()
    {
        if (!BCMath::isValidEngine()) {
            self::markTestSkipped('BCMath extension is not available.');
        }
        BCMath::setModExpEngine('DefaultEngine');
    }

    public function getInstance($x = 0, $base = 10)
    {
        return new BCMath($x, $base);
    }

    /**
     * @group github2089
     */
    public function testBCSscale()
    {
        bcscale(1);
        $number = new BCMath('115792089210356248762697446949407573530086143415290314195533631308867097853951', 10);
        $this->assertTrue($number->isPrime());
        bcscale(0);
    }

    public static function getStaticClass()
    {
        return 'phpseclib3\Math\BigInteger\Engines\BCMath';
    }
}
