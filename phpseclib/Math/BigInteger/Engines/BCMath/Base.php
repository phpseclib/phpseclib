<?php

/**
 * Modular Exponentiation Engine
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

namespace phpseclib\Math\BigInteger\Engines\BCMath;

use phpseclib\Math\BigInteger\Engines\BCMath;

/**
 * Sliding Window Exponentiation Engine
 *
 * @package PHP
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class Base extends BCMath
{
    /**#@+
     * @access private
    */
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
    /**#@-*/

    /**
     * Test for engine validity
     *
     * @return bool
     */
    public static function isValidEngine()
    {
        return static::class != __CLASS__;
    }

    /**
     * Performs modular exponentiation.
     *
     * @param \phpseclib\Math\BigInteger\Engines\BCMath $x
     * @param \phpseclib\Math\BigInteger\Engines\BCMath $e
     * @param \phpseclib\Math\BigInteger\Engines\BCMath $n
     * @param string $class
     * @return \phpseclib\Math\BigInteger\Engines\BCMath
     */
    public static function powModHelper(BCMath $x, BCMath $e, BCMath $n, $class)
    {
        if (empty($e->value)) {
            $temp = new $class();
            $temp->value = '1';
            return $x->normalize($temp);
        }

        if ($e->value == '1') {
            $temp = bcdiv($x, $n);
            return $x->normalize($temp);
        }

        return $x->normalize(static::slidingWindow($x, $e, $n, $class));
    }

    /**
     * Modular reduction preperation
     *
     * @param string $x
     * @param string $n
     * @param string $class
     * @see self::slidingWindow()
     * @return string
     */
    protected static function prepareReduce($x, $n, $class)
    {
        return static::reduce($x, $n);
    }

    /**
     * Modular multiply
     *
     * @param string $x
     * @param string $y
     * @param string $n
     * @param string $class
     * @see self::slidingWindow()
     * @return string
     */
    protected static function multiplyReduce($x, $y, $n, $class)
    {
        return static::reduce(bcmul($x, $y), $n);
    }

    /**
     * Modular square
     *
     * @param string $x
     * @param string $n
     * @param string $class
     * @see self::slidingWindow()
     * @return string
     */
    protected static function squareReduce($x, $n, $class)
    {
        return static::reduce(bcmul($x, $x), $n);
    }
}