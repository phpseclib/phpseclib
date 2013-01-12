<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

abstract class PhpseclibTestCase extends PHPUnit_Framework_TestCase
{
	/**
	* @param string $constant
	* @param mixed $expected
	*
	* @return null
	*/
	static protected function ensureModeConstant($constant, $expected)
	{
		if (defined($constant))
		{
			$value = constant($constant);

			if ($value !== $expected)
			{
				self::markTestSkipped(sprintf(
					"Skipping test because mode constant %s is %s instead of %s",
					$constant,
					$value,
					$expected
				));
			}
		}
		else
		{
			define($constant, $expected);
		}
	}
}
