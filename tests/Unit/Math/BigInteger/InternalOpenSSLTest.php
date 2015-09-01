<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Unit_Math_BigInteger_InternalOpenSSLTest extends Unit_Math_BigInteger_TestCase
{
    public static function setUpBeforeClass()
    {
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('openssl_public_encrypt() function is not available.');
        }

        parent::setUpBeforeClass();

        self::ensureConstant('MATH_BIGINTEGER_MODE', MATH_BIGINTEGER_MODE_INTERNAL);
    }
}
