<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Phpseclib_Test_Unit_Math_BigInteger_InternalOpenSSLTest extends Phpseclib_Test_Unit_Math_BigInteger_TestCase
{
    static public function setUpBeforeClass()
    {
        if (!function_exists('openssl_public_encrypt')) {
            self::markTestSkipped('openssl_public_encrypt() function is not available.');
        }

        parent::setUpBeforeClass();

        self::ensureConstant('MATH_BIGINTEGER_MODE', MATH_BIGINTEGER_MODE_INTERNAL);
    }
}
