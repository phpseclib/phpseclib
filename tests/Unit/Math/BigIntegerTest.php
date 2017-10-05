<?php

use phpseclib\Math\BigInteger;
use phpseclib\Math\BigInteger\Engines\BCMath;
use phpseclib\Math\BigInteger\Engines\GMP;
use phpseclib\Math\BigInteger\Engines\PHP32;
use phpseclib\Math\BigInteger\Engines\PHP64;

class Unit_Math_BigIntegerTest extends PhpseclibTestCase
{

	/**
	 * @param string $className
	 * @param bool   $isValid
	 */
	private static function mockEngine($className, $isValid) {
		eval(<<<ENGINE
namespace phpseclib\Math\BigInteger\Engines;
class ${className} extends \phpseclib\Math\BigInteger\Engines\Engine {
	public function __construct(){} 
	public static function isValidEngine() { return ${isValid}; }
	public static function setModExpEngine(\$engine){} 
	public function toString() { return __CLASS__; }
}
ENGINE
		);
	}

	public static function provideBadConfigurationException() {
		return [
			[
				GMP::class,
				['GMP', true],
			],
			[
				PHP64::class,
				['GMP', false],
				['PHP64', true],
			],
			[
				BCMath::class,
				['GMP', false],
				['PHP64', false],
				['BCMath', true],
			],
			[
				PHP32::class,
				['GMP', false],
				['PHP64', false],
				['BCMath', false],
				['PHP32', true],
			],
		];
	}

	/**
	 * BigInteger should choose another engine if one is not valid
	 * @dataProvider         provideBadConfigurationException
	 * @preserveGlobalState  disabled
	 * @runInSeparateProcess mocks must not disturb other tests
	 * @param string  $expectedEngineClass
	 * @param array[] ...$engines
	 */
	public function testBadConfigurationException($expectedEngineClass, array ...$engines) {
		foreach ($engines as $engine) {
			static::mockEngine($engine[0], $engine[1]);
		}

		$bigint = new BigInteger();

		static::assertSame($expectedEngineClass, $bigint->toString());
	}
}
