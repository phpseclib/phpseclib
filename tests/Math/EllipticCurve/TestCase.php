<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

abstract class Math_EllipticCurve_TestCase extends PhpseclibTestCase
{
	protected $curve;
	protected $factory;

	public function setUp()
	{
		parent::setUp();

		$this->factory = new Math_EcFpCurveFactory;
	}

	public function assertPointEquals(Math_EcFpCurvePoint $expected, Math_EcFpCurvePoint $actual)
	{
		$this->assertSame(
			$expected->toString(),
			$actual->toString(),
			'Failed asserting that two elliptic curve points are equal.'
		);
	}

	protected function pointFromHex($x_hex, $y_hex)
	{
		return new Math_EcFpCurvePoint(
			$this->curve,
			$this->integerFromHex($x_hex),
			$this->integerFromHex($y_hex)
		);
	}

	protected function integerFromHex($hex)
	{
		return new Math_BigInteger($this->cleanHex($hex), 16);
	}

	protected function cleanHex($hex)
	{
		return str_replace(' ', '', $hex);
	}
}
