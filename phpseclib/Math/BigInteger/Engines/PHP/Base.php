<?php

/**
 * PHP Modular Exponentiation Engine
 *
 * PHP version 5 and 7
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://pear.php.net/package/Math_BigInteger
 */

declare(strict_types=1);

namespace phpseclib3\Math\BigInteger\Engines\PHP;

use phpseclib3\Math\BigInteger\Engines\PHP;

/**
 * PHP Modular Exponentiation Engine
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Base extends PHP
{
    /**
     * Cache constants
     *
     * $cache[self::VARIABLE] tells us whether or not the cached data is still valid.
     */
    const VARIABLE = 0;
    /**
     * $cache[self::DATA] contains the cached data.
     */
    const DATA = 1;

    /**
     * Test for engine validity
     */
    public static function isValidEngine(): bool
    {
        return static::class != __CLASS__;
    }

    /**
     * Performs modular exponentiation.
     *
     * The most naive approach to modular exponentiation has very unreasonable requirements, and
     * and although the approach involving repeated squaring does vastly better, it, too, is impractical
     * for our purposes.  The reason being that division - by far the most complicated and time-consuming
     * of the basic operations (eg. +,-,*,/) - occurs multiple times within it.
     *
     * Modular reductions resolve this issue.  Although an individual modular reduction takes more time
     * then an individual division, when performed in succession (with the same modulo), they're a lot faster.
     *
     * The two most commonly used modular reductions are Barrett and Montgomery reduction.  Montgomery reduction,
     * although faster, only works when the gcd of the modulo and of the base being used is 1.  In RSA, when the
     * base is a power of two, the modulo - a product of two primes - is always going to have a gcd of 1 (because
     * the product of two odd numbers is odd), but what about when RSA isn't used?
     *
     * In contrast, Barrett reduction has no such constraint.  As such, some bigint implementations perform a
     * Barrett reduction after every operation in the modpow function.  Others perform Barrett reductions when the
     * modulo is even and Montgomery reductions when the modulo is odd.  BigInteger.java's modPow method, however,
     * uses a trick involving the Chinese Remainder Theorem to factor the even modulo into two numbers - one odd and
     * the other, a power of two - and recombine them, later.  This is the method that this modPow function uses.
     * {@link http://islab.oregonstate.edu/papers/j34monex.pdf Montgomery Reduction with Even Modulus} elaborates.
     */
    protected static function powModHelper(PHP $x, PHP $e, PHP $n, string $class): PHP
    {
        if (empty($e->value)) {
            $temp = new $class();
            $temp->value = [1];
            return $x->normalize($temp);
        }

        if ($e->value == [1]) {
            [, $temp] = $x->divide($n);
            return $x->normalize($temp);
        }

        if ($e->value == [2]) {
            $temp = new $class();
            $temp->value = $class::square($x->value);
            [, $temp] = $temp->divide($n);
            return $x->normalize($temp);
        }

        return $x->normalize(static::slidingWindow($x, $e, $n, $class));
    }

    /**
     * Modular reduction preparation
     *
     * @see self::slidingWindow()
     */
    protected static function prepareReduce(array $x, array $n, string $class): array
    {
        return static::reduce($x, $n, $class);
    }

    /**
     * Modular multiply
     *
     * @see self::slidingWindow()
     */
    protected static function multiplyReduce(array $x, array $y, array $n, string $class): array
    {
        $temp = $class::multiplyHelper($x, false, $y, false);
        return static::reduce($temp[self::VALUE], $n, $class);
    }

    /**
     * Modular square
     *
     * @see self::slidingWindow()
     */
    protected static function squareReduce(array $x, array $n, string $class): array
    {
        return static::reduce($class::square($x), $n, $class);
    }
}
