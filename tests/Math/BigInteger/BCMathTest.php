<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib\Math\BigInteger;

use phpseclib\Math\BigInteger;

class BCMathTest extends \phpseclib\Math\BigInteger\TestCase
{
	static public function setUpBeforeClass()
	{
		if (!extension_loaded('bcmath'))
		{
			self::markTestSkipped('BCMath extension is not available.');
		}

		parent::setUpBeforeClass();

		BigInteger::setMode(BigInteger::MODE_BCMATH);
	}
}
