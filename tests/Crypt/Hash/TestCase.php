<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib\Crypt\Hash;

use phpseclib\Crypt\Hash;

abstract class TestCase extends \phpseclib\AbstractTestCase
{
	static public function setUpBeforeClass()
	{
		Hash::setMode(Hash::MODE_INTERNAL);
	}

	public function setUp()
	{
		if (Hash::getMode() !== Hash::MODE_INTERNAL)
		{
			$this->markTestSkipped('Skipping test because Hash::$mode is not defined as Hash::MODE_INTERNAL.');
		}
	}

	protected function assertHashesTo(Hash $hash, $message, $expected)
	{
		$this->assertEquals(
			strtolower($expected),
			bin2hex($hash->hash($message)),
			sprintf("Failed asserting that '%s' hashes to '%s'.", $message, $expected)
		);
	}

	protected function assertHMACsTo(Hash $hash, $key, $message, $expected)
	{
		$hash->setKey($key);

		$this->assertEquals(
			strtolower($expected),
			bin2hex($hash->hash($message)),
			sprintf("Failed asserting that '%s' HMACs to '%s' with key '%s'.", $message, $expected, $key)
		);
	}
}
