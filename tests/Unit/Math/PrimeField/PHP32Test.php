<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Unit\Math\PrimeField;

use phpseclib3\Math\BigInteger;
use phpseclib3\Math\BigInteger\Engines\PHP32;

class PHP32Test extends TestCase
{
    private static $defaultEngine;

    public static function setUpBeforeClass(): void
    {
        if (!PHP32::isValidEngine()) {
            self::markTestSkipped('PHP32 extension is not available.');
        }
        self::$defaultEngine = BigInteger::getEngine()[0];
        BigInteger::setEngine('PHP32');
    }

    public static function tearDownAfterClass(): void
    {
        BigInteger::setEngine(self::$defaultEngine);
    }
}
