<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Crypt_AES_ContinuousBufferTest extends Crypt_AES_TestCase
{
	// https://github.com/phpseclib/phpseclib/issues/39
	public function testGithubIssue39EncryptDecrypt()
	{
		$aes = new Crypt_AES(CRYPT_AES_MODE_CFB);
		$aes->enableContinuousBuffer();

		$expected = '12345678901234567';
		$actual = '';

		for ($i = 0, $strlen = strlen($expected); $i < $strlen; ++$i)
		{
			$actual .= $aes->decrypt($aes->encrypt($expected[$i]));
		}

		$this->assertEquals($expected, $actual);
	}
}
