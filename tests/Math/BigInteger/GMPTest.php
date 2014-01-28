<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib\Math\BigInteger;
 
class GMPTest extends \phpseclib\Math\BigIntegerTest
{
	static public function setUpBeforeClass()
	{
		if (!extension_loaded('gmp'))
		{
			self::markTestSkipped('GNU Multiple Precision (GMP) extension is not available.');
		}

		parent::setUpBeforeClass();

		//self::ensureConstant('MATH_BIGINTEGER_MODE', MATH_BIGINTEGER_MODE_GMP);
	}
}
