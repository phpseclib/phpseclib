<?php

/**
 * Pure-PHP 64-bit BigInteger Engine
 *
 * PHP version 5 and 7
 *
 * @category  Math
 * @package   BigInteger
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://pear.php.net/package/Math_BigInteger
 */

namespace phpseclib\Math\BigInteger\Engines;

use ParagonIE\ConstantTime\Hex;

/**
 * Pure-PHP 64-bit Engine.
 *
 * Uses 64-bit integers if int size is 8 bits
 *
 * @package PHP
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class PHP64 extends PHP
{
    /**#@+
     * Constants used by PHP.php
     */
    const BASE = 31;
    const BASE_FULL = 0x80000000;
    const MAX_DIGIT = 0x7FFFFFFF;
    const MSB = 0x40000000;

    /**
     * MAX10 in greatest MAX10LEN satisfying
     * MAX10 = 10**MAX10LEN <= 2**BASE.
     */
    const MAX10 = 1000000000;

    /**
     * MAX10LEN in greatest MAX10LEN satisfying
     * MAX10 = 10**MAX10LEN <= 2**BASE.
     */
    const MAX10LEN = 9;
    const MAX_DIGIT2 = 4611686018427387904;
    /**#@-*/

    /**
     * Modular Exponentiation Engine
     *
     * @var string
     */
    protected static $modexpEngine;

    /**
     * Engine Validity Flag
     *
     * @var bool
     */
    protected static $isValidEngine;

    /**
     * Primes > 2 and < 1000
     *
     * @var array
     */
    protected static $primes;

    /**
     * BigInteger(0)
     *
     * @var \phpseclib\Math\BigInteger\Engines\PHP64
     */
    protected static $zero;

    /**
     * BigInteger(1)
     *
     * @var \phpseclib\Math\BigInteger\Engines\PHP64
     */
    protected static $one;

    /**
     * BigInteger(2)
     *
     * @var \phpseclib\Math\BigInteger\Engines\PHP64
     */
    protected static $two;

    /**
     * Test for engine validity
     *
     * @see parent::__construct()
     * @return bool
     */
    public static function isValidEngine()
    {
        return PHP_INT_SIZE >= 8;
    }

    /**
     * Adds two BigIntegers.
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public function add(PHP64 $y)
    {
        $temp = self::addHelper($this->value, $this->is_negative, $y->value, $y->is_negative);

        return $this->convertToObj($temp);
    }

    /**
     * Subtracts two BigIntegers.
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public function subtract(PHP64 $y)
    {
        $temp = self::subtractHelper($this->value, $this->is_negative, $y->value, $y->is_negative);

        return $this->convertToObj($temp);
    }

    /**
     * Multiplies two BigIntegers.
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public function multiply(PHP64 $y)
    {
        $temp = self::multiplyHelper($this->value, $this->is_negative, $y->value, $y->is_negative);

        return $this->convertToObj($temp);
    }

    /**
     * Divides two BigIntegers.
     *
     * Returns an array whose first element contains the quotient and whose second element contains the
     * "common residue".  If the remainder would be positive, the "common residue" and the remainder are the
     * same.  If the remainder would be negative, the "common residue" is equal to the sum of the remainder
     * and the divisor (basically, the "common residue" is the first positive modulo).
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public function divide(PHP64 $y)
    {
        return $this->divideHelper($y);
    }

    /**
     * Calculates modular inverses.
     *
     * Say you have (30 mod 17 * x mod 17) mod 17 == 1.  x can be found using modular inverses.
     */
    public function modInverse(PHP64 $n)
    {
        return $this->modInverseHelper($n);
    }

    /**
     * Calculates modular inverses.
     *
     * Say you have (30 mod 17 * x mod 17) mod 17 == 1.  x can be found using modular inverses.
     */
    public function extendedGCD(PHP64 $n)
    {
        return $this->extendedGCDHelper($n);
    }

    /**
     * Calculates the greatest common divisor
     *
     * Say you have 693 and 609.  The GCD is 21.
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public function gcd(PHP64 $n)
    {
        extract($this->extendedGCD($n));
        return $gcd;
    }

    /**
     * Logical And
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public function bitwise_and(PHP64 $x)
    {
        return $this->bitwiseAndHelper($x);
    }

    /**
     * Logical Or
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public function bitwise_or(PHP64 $x)
    {
        return $this->bitwiseOrHelper($x);
    }

    /**
     * Logical Exlusive Or
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public function bitwise_xor(PHP64 $x)
    {
        return $this->bitwiseXorHelper($x);
    }

    /**
     * Compares two numbers.
     *
     * Although one might think !$x->compare($y) means $x != $y, it, in fact, means the opposite.  The reason for this is
     * demonstrated thusly:
     *
     * $x  > $y: $x->compare($y)  > 0
     * $x  < $y: $x->compare($y)  < 0
     * $x == $y: $x->compare($y) == 0
     *
     * Note how the same comparison operator is used.  If you want to test for equality, use $x->equals($y).
     *
     * @return int < 0 if $this is less than $y; > 0 if $this is greater than $y, and 0 if they are equal.
     * @access public
     * @see self::equals()
     * @internal Could return $this->subtract($x), but that's not as fast as what we do do.
     */
    public function compare(PHP64 $y)
    {
        return parent::compareHelper($this->value, $this->is_negative, $y->value, $y->is_negative);
    }

    /**
     * Tests the equality of two numbers.
     *
     * If you need to see if one number is greater than or less than another number, use BigInteger::compare()
     *
     * @return bool
     */
    public function equals(PHP64 $x)
    {
        return $this->value === $x->value && $this->is_negative == $x->is_negative;
    }

    /**
     * Performs modular exponentiation.
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public function modPow(PHP64 $e, PHP64 $n)
    {
        return $this->powModOuter($e, $n);
    }

    /**
     * Performs modular exponentiation.
     *
     * Alias for modPow().
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public function powMod(PHP64 $e, PHP64 $n)
    {
        return $this->powModOuter($e, $n);
    }

    /**
     * Generate a random prime number between a range
     *
     * If there's not a prime within the given range, false will be returned.
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64|false
     */
    public static function randomRangePrime(PHP64 $min, PHP64 $max)
    {
        return self::randomRangePrimeOuter($min, $max);
    }

    /**
     * Generate a random number between a range
     *
     * Returns a random number between $min and $max where $min and $max
     * can be defined using one of the two methods:
     *
     * BigInteger::randomRange($min, $max)
     * BigInteger::randomRange($max, $min)
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public static function randomRange(PHP64 $min, PHP64 $max)
    {
        return self::randomRangeHelper($min, $max);
    }

    /**
     * Performs exponentiation.
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public function pow(PHP64 $n)
    {
        return $this->powHelper($n);
    }

    /**
     * Return the minimum BigInteger between an arbitrary number of BigIntegers.
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public static function min(PHP64 ...$nums)
    {
        return self::minHelper($nums);
    }

    /**
     * Return the maximum BigInteger between an arbitrary number of BigIntegers.
     *
     * @return \phpseclib\Math\BigInteger\Engines\PHP64
     */
    public static function max(PHP64 ...$nums)
    {
        return self::maxHelper($nums);
    }

    /**
     * Tests BigInteger to see if it is between two integers, inclusive
     *
     * @return boolean
     */
    public function between(PHP64 $min, PHP64 $max)
    {
        return $this->compare($min) >= 0 && $this->compare($max) <= 0;
    }
}