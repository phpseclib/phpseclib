<?php

// declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Math;

use phpseclib3\Math\BigInteger;
use phpseclib3\Math\BigInteger\Engines\BCMath;
use phpseclib3\Math\BigInteger\Engines\GMP;
use phpseclib3\Math\BigInteger\Engines\PHP32;
use phpseclib3\Math\BigInteger\Engines\PHP64;
use phpseclib3\Tests\PhpseclibTestCase;

class BigIntegerTest extends PhpseclibTestCase
{
    /**
     */
    private static function mockEngine(string $className, bool $isValid)
    {
        eval(<<<ENGINE
// declare(strict_types=1);

namespace phpseclib3\Math\BigInteger\Engines;
class $className extends \phpseclib3\Math\BigInteger\Engines\Engine {
	public function __construct(){} 
	public static function isValidEngine() { return $isValid; }
	public static function setModExpEngine(\$engine){} 
	public function toString() { return __CLASS__; }
}
ENGINE
        );
    }

    public static function provideBadConfigurationException(): array
    {
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
     *
     * @dataProvider         provideBadConfigurationException
     * @preserveGlobalState  disabled
     * @runInSeparateProcess mocks must not disturb other tests
     * @param array[] ...$engines
     */
    public function testBadConfigurationException(string $expectedEngineClass, array ...$engines)
    {
        foreach ($engines as $engine) {
            static::mockEngine($engine[0], $engine[1]);
        }

        $bigint = new BigInteger();

        static::assertSame($expectedEngineClass, $bigint->toString());
    }
}
