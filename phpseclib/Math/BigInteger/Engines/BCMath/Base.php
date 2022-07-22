<?php

/**
 * Modular Exponentiation Engine
 *
 * PHP version 5 and 7
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://pear.php.net/package/Math_BigInteger
 */

declare(strict_types=1);

namespace phpseclib3\Math\BigInteger\Engines\BCMath;

use phpseclib3\Math\BigInteger\Engines\BCMath;

/**
 * Sliding Window Exponentiation Engine
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Base extends BCMath
{
    /**
     * Cache constants
     *
     * $cache[self::VARIABLE] tells us whether or not the cached data is still valid.
     */
    public const VARIABLE = 0;
    /**
     * $cache[self::DATA] contains the cached data.
     */
    public const DATA = 1;

    /**
     * Test for engine validity
     */
    public static function isValidEngine(): bool
    {
        return static::class != __CLASS__;
    }

    /**
     * Performs modular exponentiation.
     */
    protected static function powModHelper(BCMath $x, BCMath $e, BCMath $n, string $class): BCMath
    {
        if (empty($e->value)) {
            $temp = new $class();
            $temp->value = '1';
            return $x->normalize($temp);
        }

        return $x->normalize(static::slidingWindow($x, $e, $n, $class));
    }

    /**
     * Modular reduction preparation
     *
     * @see self::slidingWindow()
     */
    protected static function prepareReduce(string $x, string $n, string $class): string
    {
        return static::reduce($x, $n);
    }

    /**
     * Modular multiply
     *
     * @see self::slidingWindow()
     */
    protected static function multiplyReduce(string $x, string $y, string $n, string $class): string
    {
        return static::reduce(bcmul($x, $y), $n);
    }

    /**
     * Modular square
     *
     * @see self::slidingWindow()
     */
    protected static function squareReduce(string $x, string $n, string $class): string
    {
        return static::reduce(bcmul($x, $x), $n);
    }
}
