<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Test data is from http://www.nsa.gov/ia/_files/nist-routines.pdf, page 31
 * and following.
 */
class Math_EllipticCurve_NistP224Test extends Math_EllipticCurve_TestCase
{
	public function setUp()
	{
		parent::setUp();

		$this->curve = $this->factory->fromNistName('nistp224');

		$this->s = $this->pointFromHex(
			'6eca814b a59a9308 43dc814e dd6c97da 95518df3 c6fdf16e 9a10bb5b',
			'ef4b497f 0963bc8b 6aec0ca0 f259b89c d8099414 7e05dc6b 64d7bf22'
		);

		$this->t = $this->pointFromHex(
			'b72b25ae a5cb03fb 88d7e842 00296964 8e6ef23c 5d39ac90 3826bd6d',
			'c42a8a4d 34984f0b 71b5b409 1af7dceb 33ea729c 1a2dc8b4 34f10c34'
		);

		$this->d = $this->integerFromHex(
			'a78ccc30 eaca0fcc 8e36b2dd 6fbb03df 06d37f52 711e6363 aaf1d73b'
		);

		$this->e = $this->integerFromHex(
			'54d549ff c08c9659 2519d73e 71e8e070 3fc8177f a88aa77a 6ed35736'
		);
	}

	public function testAdd()
	{
		$expected = $this->pointFromHex(
			'236f26d9 e84c2f7d 776b107b d478ee0a 6d2bcfca a2162afa e8d2fd15',
			'e53cc0a7 904ce6c3 746f6a97 471297a0 b7d5cdf8 d536ae25 bb0fda70'
		);

		$this->assertPointEquals($expected, $this->s->add($this->t));
		$this->assertPointEquals($expected, $this->t->add($this->s));
	}

	public function testSubstract()
	{
		$expected = $this->pointFromHex(
			'db4112bc c8f34d4f 0b36047b ca1054f3 61541385 2a793133 5210b332',
			'90c6e830 4da48138 78c1540b 2396f411 facf787a 520a0ffb 55a8d961'
		);

		$this->assertPointEquals($expected, $this->s->subtract($this->t));
	}

	public function testDouble()
	{
		$expected = $this->pointFromHex(
			'a9c96f21 17dee0f2 7ca56850 ebb46efa d8ee2685 2f165e29 cb5cdfc7',
			'adf18c84 cf77ced4 d76d4930 417d9579 207840bf 49bfbf58 37dfdd7d'
		);

		$this->assertPointEquals($expected, $this->s->add($this->s));
	}

	public function testMultiply()
	{
		$expected = $this->pointFromHex(
			'96a7625e 92a8d72b ff1113ab db95777e 736a14c6 fdaacc39 2702bca4',
			'0f8e5702 942a3c5e 13cd2fd5 80191525 8b43dfad c70d15db ada3ed10'
		);

		$this->assertPointEquals($expected, $this->s->multiply($this->d));
	}

	public function testMultiplyAndAdd()
	{
		$expected = $this->pointFromHex(
			'dbfe2958 c7b2cda1 302a67ea 3ffd94c9 18c5b350 ab838d52 e288c83e',
			'2f521b83 ac3b0549 ff4895ab cc7f0c5a 861aacb8 7acbc5b8 147bb18b'
		);

		// R = d * S + e * T
		$actual = $this->s->multiply($this->d)->add($this->t->multiply($this->e));

		$this->assertPointEquals($expected, $actual);
	}
}
