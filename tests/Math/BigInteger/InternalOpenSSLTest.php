<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib\Math\BigInteger;

use phpseclib\Math\BigInteger;

class InternalOpenSSLTest extends \phpseclib\Math\BigInteger\TestCase
{
	static public function setUpBeforeClass()
	{
		if (!function_exists('openssl_public_encrypt'))
		{
			self::markTestSkipped('openssl_public_encrypt() function is not available.');
		}

		parent::setUpBeforeClass();

		BigInteger::setMode(BigInteger::MODE_INTERNAL);
	}
}
