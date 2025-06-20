<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Unit\Math\PrimeField;

use phpseclib3\Math\BigInteger;
use phpseclib3\Math\BigInteger\Engines\PHP64;

class PHP64Test extends TestCase
{
    private static $defaultEngine;

    public static function setUpBeforeClass()
    {
        if (!PHP64::isValidEngine()) {
            self::markTestSkipped('PHP64 engine is not available.');
        }
        self::$defaultEngine = BigInteger::getEngine()[0];
        BigInteger::setEngine('PHP64');
    }

    public static function tearDownAfterClass()
    {
        BigInteger::setEngine(self::$defaultEngine);
    }
}
