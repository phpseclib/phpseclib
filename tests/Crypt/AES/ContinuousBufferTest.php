<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib\Crypt\AES;

use phpseclib\Crypt\AES;

class ContinuousBufferTest extends \phpseclib\Crypt\AES\TestCase
{
	// String intented
	protected $modes = array(
		AES::MODE_CTR,
		AES::MODE_OFB,
		AES::MODE_CFB,
	);

	protected $plaintexts = array(
		'',
		'12345678901234567', // https://github.com/phpseclib/phpseclib/issues/39
		"\xDE\xAD\xBE\xAF",
		':-):-):-):-):-):-)', // https://github.com/phpseclib/phpseclib/pull/43
	);

	protected $ivs = array(
		'',
		'test123',
	);

	protected $keys = array(
		'',
		':-8',		// https://github.com/phpseclib/phpseclib/pull/43
		'FOOBARZ',
	);

	/**
	* Produces all combinations of test values.
	*
	* @return array
	*/
	public function allCombinations()
	{
		$result = array();

		foreach ($this->modes as $mode)
		foreach ($this->plaintexts as $plaintext)
		foreach ($this->ivs as $iv)
		foreach ($this->keys as $key)
			$result[] = array($mode, $plaintext, $iv, $key);

		return $result;
	}

	/**
	* @dataProvider allCombinations
	*/
	public function testEncryptDecrypt($mode, $plaintext, $iv, $key)
	{
		$aes = new AES($mode);
		$aes->enableContinuousBuffer();
		$aes->setIV($iv);
		$aes->setKey($key);

		$actual = '';
		for ($i = 0, $strlen = strlen($plaintext); $i < $strlen; ++$i)
		{
			$actual .= $aes->decrypt($aes->encrypt($plaintext[$i]));
		}

		$this->assertEquals($plaintext, $actual);
	}
}
