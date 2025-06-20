<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Unit\Math\PrimeField;

use phpseclib3\Math\BigInteger;
use phpseclib3\Math\BigInteger\Engines\BCMath;

class BCMathTest extends TestCase
{
    private static $defaultEngine;

    public static function setUpBeforeClass()
    {
        if (!BCMath::isValidEngine()) {
            self::markTestSkipped('BCMath extension is not available.');
        }
        self::$defaultEngine = BigInteger::getEngine()[0];
        BigInteger::setEngine('BCMath');
    }

    public static function tearDownAfterClass()
    {
        BigInteger::setEngine(self::$defaultEngine);
    }
}
