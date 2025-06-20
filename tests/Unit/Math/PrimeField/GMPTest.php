<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Unit\Math\PrimeField;

use phpseclib3\Math\BigInteger;
use phpseclib3\Math\BigInteger\Engines\GMP;

class GMPTest extends TestCase
{
    private static $defaultEngine;

    public static function setUpBeforeClass(): void
    {
        if (!GMP::isValidEngine()) {
            self::markTestSkipped('GMP extension is not available.');
        }
        self::$defaultEngine = BigInteger::getEngine()[0];
        BigInteger::setEngine('GMP');
    }

    public static function tearDownAfterClass(): void
    {
        BigInteger::setEngine(self::$defaultEngine);
    }
}
