<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Math_BigInteger_InternalTest extends Unit_Math_BigInteger_TestCase
{
    static public function setUpBeforeClass()
    {
        parent::setUpBeforeClass();

        self::ensureConstant('MATH_BIGINTEGER_MODE', MATH_BIGINTEGER_MODE_INTERNAL);
        self::ensureConstant('MATH_BIGINTEGER_OPENSSL_DISABLE', true);
    }

    public function testInternalRepresentation()
    {
        $x = new \phpseclib\phpseclib\Math_BigInteger('FFFFFFFFFFFFFFFFC90FDA', 16);
        $y = new \phpseclib\phpseclib\Math_BigInteger("$x");
        $this->assertSame($x->value, $y->value);
    }
}
