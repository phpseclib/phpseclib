<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Test data is from http://www.nsa.gov/ia/_files/nist-routines.pdf, page 27
 * and following.
 */
class Math_EllipticCurve_NistP192Test extends Math_EllipticCurve_TestCase
{
	public function setUp()
	{
		parent::setUp();

		$this->curve = $this->factory->fromNistName('nistp192');

		$this->s = $this->pointFromHex(
			'd458e7d1 27ae671b 0c330266 d2467693 53a01207 3e97acf8',
			'32593050 0d851f33 6bddc050 cf7fb11b 5673a164 5086df3b'
		);

		$this->t = $this->pointFromHex(
			'f22c4395 213e9ebe 67ddecdd 87fdbd01 be16fb05 9b9753a4',
			'26442409 6af2b359 7796db48 f8dfb41f a9cecc97 691a9c79'
		);

		$this->d = $this->integerFromHex(
			'a78a236d 60baec0c 5dd41b33 a542463a 8255391a f64c74ee'
		);

		$this->e = $this->integerFromHex(
			'c4be3d53 ec3089e7 1e4de8ce ab7cce88 9bc393cd 85b972bc'
		);
	}

	public function testAdd()
	{
		$expected = $this->pointFromHex(
			'48e1e409 6b9b8e5c a9d0f1f0 77b8abf5 8e843894 de4d0290',
			'408fa77c 797cd7db fb16aa48 a3648d3d 63c94117 d7b6aa4b'
		);

		$this->assertPointEquals($expected, $this->s->add($this->t));
		$this->assertPointEquals($expected, $this->t->add($this->s));
	}

	public function testSubstract()
	{
		$expected = $this->pointFromHex(
			'fc9683cc 5abfb4fe 0cc8cc3b c9f61eab c4688f11 e9f64a2e',
			'093e31d0 0fb78269 732b1bd2 a73c23cd d31745d0 523d816b'
		);

		$this->assertPointEquals($expected, $this->s->subtract($this->t));
	}

	public function testDouble()
	{
		$expected = $this->pointFromHex(
			'30c5bc6b 8c7da253 54b373dc 14dd8a0e ba42d25a 3f6e6962',
			'0dde14bc 4249a721 c407aedb f011e2dd bbcb2968 c9d889cf'
		);

		$this->assertPointEquals($expected, $this->s->add($this->s));
	}

	public function testMultiply()
	{
		$expected = $this->pointFromHex(
			'1faee420 5a4f669d 2d0a8f25 e3bcec9a 62a69529 65bf6d31',
			'5ff2cdfa 508a2581 89236708 7c696f17 9e7a4d7e 8260fb06'
		);

		$this->assertPointEquals($expected, $this->s->multiply($this->d));
	}

	public function testMultiplyAndAdd()
	{
		$expected = $this->pointFromHex(
			'019f64ee d8fa9b72 b7dfea82 c17c9bfa 60ecb9e1 778b5bde',
			'16590c5f cd8655fa 4ced33fb 800e2a7e 3c61f35d 83503644'
		);

		// R = d * S + e * T
		$actual = $this->s->multiply($this->d)->add($this->t->multiply($this->e));

		$this->assertPointEquals($expected, $actual);
	}
}
