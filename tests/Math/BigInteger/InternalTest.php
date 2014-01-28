<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib\Math\BigInteger;
 
class InternalTest extends \phpseclib\Math\BigIntegerTest
{
	static public function setUpBeforeClass()
	{
		parent::setUpBeforeClass();

		//self::ensureConstant('MATH_BIGINTEGER_MODE', MATH_BIGINTEGER_MODE_INTERNAL);
		//self::ensureConstant('MATH_BIGINTEGER_OPENSSL_DISABLE', true);
	}
}
