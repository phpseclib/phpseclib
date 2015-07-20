<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Unit_Math_BigInteger_BCMathTest extends Unit_Math_BigInteger_TestCase
{
    public static function setUpBeforeClass()
    {
        if (!extension_loaded('bcmath')) {
            self::markTestSkipped('BCMath extension is not available.');
        }

        parent::setUpBeforeClass();

        self::ensureConstant('MATH_BIGINTEGER_MODE', \phpseclib\Math\BigInteger::MODE_BCMATH);
    }
}
