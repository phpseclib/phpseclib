<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Pure-PHP arbitrary precision integer arithmetic library.
 *
 * Supports base-2, base-10, base-16, and base-256 numbers.  Uses the GMP or BCMath extensions, if available,
 * and an internal implementation, otherwise.
 *
 * PHP versions 4 and 5
 *
 * {@internal (all DocBlock comments regarding implementation - such as the one that follows - refer to the 
 * {@link MATH_BIGINTEGER_MODE_INTERNAL MATH_BIGINTEGER_MODE_INTERNAL} mode)
 *
 * Math_BigInteger uses base-2**26 to perform operations such as multiplication and division and
 * base-2**52 (ie. two base 2**26 digits) to perform addition and subtraction.  Because the largest possible
 * value when multiplying two base-2**26 numbers together is a base-2**52 number, double precision floating
 * point numbers - numbers that should be supported on most hardware and whose significand is 53 bits - are
 * used.  As a consequence, bitwise operators such as >> and << cannot be used, nor can the modulo operator %,
 * which only supports integers.  Although this fact will slow this library down, the fact that such a high
 * base is being used should more than compensate.
 *
 * When PHP version 6 is officially released, we'll be able to use 64-bit integers.  This should, once again,
 * allow bitwise operators, and will increase the maximum possible base to 2**31 (or 2**62 for addition /
 * subtraction).
 *
 * Useful resources are as follows:
 *
 *  - {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf Handbook of Applied Cryptography (HAC)}
 *  - {@link http://math.libtomcrypt.com/files/tommath.pdf Multi-Precision Math (MPM)}
 *  - Java's BigInteger classes.  See /j2se/src/share/classes/java/math in jdk-1_5_0-src-jrl.zip
 *
 * One idea for optimization is to use the comba method to reduce the number of operations performed.
 * MPM uses this quite extensively.  The following URL elaborates:
 *
 * {@link http://www.everything2.com/index.pl?node_id=1736418}}}
 *
 * Here's a quick 'n dirty example of how to use this library:
 * <code>
 * <?php
 *    include('Math/BigInteger.php');
 *
 *    $a = new Math_BigInteger(2);
 *    $b = new Math_BigInteger(3);
 *
 *    $c = $a->add($b);
 *
 *    echo $c->toString(); // outputs 5
 * ?>
 * </code>
 *
 * LICENSE: This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA  02111-1307  USA
 *
 * @category   Math
 * @package    Math_BigInteger
 * @author     Jim Wigginton <terrafrost@php.net>
 * @copyright  MMVI Jim Wigginton
 * @license    http://www.gnu.org/licenses/lgpl.txt
 * @version    $Id: BigInteger.php,v 1.4 2008-05-25 07:28:57 terrafrost Exp $
 * @link       http://pear.php.net/package/Math_BigInteger
 */

/**
 * Include PHP_Compat module bcpowmod since that function does not exist in PHP4:
 * {@link http://pear.php.net/package/PHP_Compat/}
 * {@link http://php.net/function.bcpowmod}
 */
require_once 'PHP/Compat/Function/bcpowmod.php';
/**
 * Include PHP_Compat module array_fill since that function requires PHP4.2.0+:
 * {@link http://pear.php.net/package/PHP_Compat/}
 * {@link http://php.net/function.array_fill}
 */
require_once 'PHP/Compat/Function/array_fill.php';

/**#@+
 * @access private
 * @see Math_BigInteger::_slidingWindow()
 */
/**
 * @see Math_BigInteger::_montgomery()
 * @see Math_BigInteger::_undoMontgomery()
 */
define('MATH_BIGINTEGER_MONTGOMERY', 0);
/**
 * @see Math_BigInteger::_barrett()
 */
define('MATH_BIGINTEGER_BARRETT', 1);
/**
 * @see Math_BigInteger::_mod2()
 */
define('MATH_BIGINTEGER_POWEROF2', 2);
/**
 * @see Math_BigInteger::_remainder()
 */
define('MATH_BIGINTEGER_CLASSIC', 3);
/**
 * @see Math_BigInteger::_copy()
 */
define('MATH_BIGINTEGER_NONE', 4);
/**#@-*/

/**#@+
 * @access private
 * @see Math_BigInteger::_montgomery()
 * @see Math_BigInteger::_barrett()
 */
/**
 * $cache[MATH_BIGINTEGER_VARIABLE] tells us whether or not the cached data is still valid.
 */
define('MATH_BIGINTEGER_VARIABLE', 0);
/**
 * $cache[MATH_BIGINTEGER_DATA] contains the cached data.
 */
define('MATH_BIGINTEGER_DATA', 1);
/**#@-*/

/**#@+
 * @access private
 * @see Math_BigInteger::Math_BigInteger()
 */
/**
 * To use the pure-PHP implementation
 */
define('MATH_BIGINTEGER_MODE_INTERNAL', 1);
/**
 * To use the BCMath library
 *
 * (if enabled; otherwise, the internal implementation will be used)
 */
define('MATH_BIGINTEGER_MODE_BCMATH', 2);
/**
 * To use the GMP library
 *
 * (if present; otherwise, either the BCMath or the internal implementation will be used)
 */
define('MATH_BIGINTEGER_MODE_GMP', 3);
/**#@-*/

/**
 * Pure-PHP arbitrary precission integer arithmetic library. Supports base-2, base-10, base-16, and base-256
 * numbers.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @version 1.0.0RC3
 * @access  public
 * @package Math_BigInteger
 */
class Math_BigInteger {
    /**
     * Holds the BigInteger's value.
     *
     * @var Array
     * @access private
     */
    var $value;

    /**
     * Holds the BigInteger's magnitude.
     *
     * @var Boolean
     * @access private
     */
    var $is_negative = false;

    /**
     * Converts base-2, base-10, base-16, and binary strings (eg. base-256) to BigIntegers.
     *
     * If the second parameter - $base - is negative, then it will be assumed that the number's are encoded using
     * two's compliment.  The sole exception to this is -10, which is treated the same as 10 is.
     *
     * Here's a quick 'n dirty example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math_BigInteger('0x32', 16); // 50 in base-16
     *
     *    echo $a->toString(); // outputs 50
     * ?>
     * </code>
     *
     * @param optional $x base-10 number or base-$base number if $base set.
     * @param optional integer $base
     * @return Math_BigInteger
     * @access public
     */
    function Math_BigInteger($x = 0, $base = 10)
    {
        if ( !defined('MATH_BIGINTEGER_MODE') ) {
            switch (true) {
                case extension_loaded('gmp'):
                    define('MATH_BIGINTEGER_MODE', MATH_BIGINTEGER_MODE_GMP);
                    break;
                case extension_loaded('bcmath'):
                    define('MATH_BIGINTEGER_MODE', MATH_BIGINTEGER_MODE_BCMATH);
                    break;
                default:
                    define('MATH_BIGINTEGER_MODE', MATH_BIGINTEGER_MODE_INTERNAL);
            }
        }

        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                $this->value = gmp_init(0);
                break;
            case MATH_BIGINTEGER_MODE_BCMATH:
                $this->value = '0';
                break;
            default:
                $this->value = array();
        }

        if ($x === 0) {
            return;
        }

        switch ($base) {
            case -256:
                if (ord($x[0]) & 0x80) {
                    $x = ~$x;
                    $this->is_negative = true;
                }
            case  256:
                switch ( MATH_BIGINTEGER_MODE ) {
                    case MATH_BIGINTEGER_MODE_GMP:
                        $temp = unpack('H*hex', $x);
                        $sign = $this->is_negative ? '-' : '';
                        $this->value = gmp_init($sign . '0x' . $temp['hex']);
                        break;
                    case MATH_BIGINTEGER_MODE_BCMATH:
                        // round $len to the nearest 4 (thanks, DavidMJ!)
                        $len = (strlen($x) + 3) & 0xFFFFFFFC;

                        $x = str_pad($x, $len, chr(0), STR_PAD_LEFT);

                        for ($i = 0; $i < $len; $i+= 4) {
                            $this->value = bcmul($this->value, '4294967296'); // 4294967296 == 2**32
                            $this->value = bcadd($this->value, 0x1000000 * ord($x[$i]) + ((ord($x[$i + 1]) << 16) | (ord($x[$i + 2]) << 8) | ord($x[$i + 3])));
                        }

                        if ($this->is_negative) {
                            $this->value = '-' . $this->value;
                        }

                        break;
                    // converts a base-2**8 (big endian / msb) number to base-2**26 (little endian / lsb)
                    case MATH_BIGINTEGER_MODE_INTERNAL:
                        while (strlen($x)) {
                            $this->value[] = $this->_bytes2int($this->_base256_rshift($x, 26));
                        }
                }

                if ($this->is_negative) {
                    if (MATH_BIGINTEGER_MODE != MATH_BIGINTEGER_MODE_INTERNAL) {
                        $this->is_negative = false;
                    }
                    $temp = $this->add(new Math_BigInteger('-1'));
                    $this->value = $temp->value;
                }
                break;
            case  16:
            case -16:
                if ($base > 0 && $x[0] == '-') {
                    $this->is_negative = true;
                    $x = substr($x, 1);
                }

                $x = preg_replace('#^(?:0x)?([A-Fa-f0-9]*).*#', '$1', $x);

                $is_negative = false;
                if ($base < 0 && hexdec($x[0]) >= 8) {
                    $this->is_negative = $is_negative = true;
                    $x = bin2hex(~pack('H*', $x));
                }

                switch ( MATH_BIGINTEGER_MODE ) {
                    case MATH_BIGINTEGER_MODE_GMP:
                        $temp = $this->is_negative ? '-0x' . $x : '0x' . $x;
                        $this->value = gmp_init($temp);
                        $this->is_negative = false;
                        break;
                    case MATH_BIGINTEGER_MODE_BCMATH:
                        $x = ( strlen($x) & 1 ) ? '0' . $x : $x;
                        $temp = new Math_BigInteger(pack('H*', $x), 256);
                        $this->value = $this->is_negative ? '-' . $temp->value : $temp->value;
                        $this->is_negative = false;
                        break;
                    case MATH_BIGINTEGER_MODE_INTERNAL:
                        $x = ( strlen($x) & 1 ) ? '0' . $x : $x;
                        $temp = new Math_BigInteger(pack('H*', $x), 256);
                        $this->value = $temp->value;
                }

                if ($is_negative) {
                    $temp = $this->add(new Math_BigInteger('-1'));
                    $this->value = $temp->value;
                }
                break;
            case  10:
            case -10:
                $x = preg_replace('#^(-?[0-9]*).*#', '$1', $x);

                switch ( MATH_BIGINTEGER_MODE ) {
                    case MATH_BIGINTEGER_MODE_GMP:
                        $this->value = gmp_init($x);
                        break;
                    case MATH_BIGINTEGER_MODE_BCMATH:
                        // explicitly casting $x to a string is necessary, here, since doing $x[0] on -1 yields different
                        // results then doing it on '-1' does (modInverse does $x[0])
                        $this->value = (string) $x;
                        break;
                    case MATH_BIGINTEGER_MODE_INTERNAL:
                        $temp = new Math_BigInteger();

                        // array(10000000) is 10**7 in base-2**26.  10**7 is the closest to 2**26 we can get without passing it.
                        $multiplier = new Math_BigInteger();
                        $multiplier->value = array(10000000);

                        if ($x[0] == '-') {
                            $this->is_negative = true;
                            $x = substr($x, 1);
                        }

                        $x = str_pad($x, strlen($x) + (6 * strlen($x)) % 7, 0, STR_PAD_LEFT);

                        while (strlen($x)) {
                            $temp = $temp->multiply($multiplier);
                            $temp = $temp->add(new Math_BigInteger($this->_int2bytes(substr($x, 0, 7)), 256));
                            $x = substr($x, 7);
                        }

                        $this->value = $temp->value;
                }
                break;
            case  2: // base-2 support originally implemented by Lluis Pamies - thanks!
            case -2:
                if ($base > 0 && $x[0] == '-') {
                    $this->is_negative = true;
                    $x = substr($x, 1);
                }

                $x = preg_replace('#^([01]*).*#', '$1', $x);
                $x = str_pad($x, strlen($x) + (3 * strlen($x)) % 4, 0, STR_PAD_LEFT);

                $str = '0x';
                while (strlen($x)) {
                   $part = substr($x, 0, 4);
                   $str.= dechex(bindec($part));
                   $x = substr($x, 4);
                }

                if ($this->is_negative) {
                    $str = '-' . $str;
                }

                $temp = new Math_BigInteger($str, 8 * $base); // ie. either -16 or +16
                $this->value = $temp->value;
                $this->is_negative = $temp->is_negative;

                break;
            default:
                // base not supported, so we'll let $this == 0
        }
    }

    /**
     * Converts a BigInteger to a byte string (eg. base-256).
     *
     * Negative numbers are saved as positive numbers, unless $twos_compliment is set to true, at which point, they're
     * saved as two's compliment.
     *
     * Here's a quick 'n dirty example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math_BigInteger('65');
     *
     *    echo $a->toBytes(); // outputs chr(65)
     * ?>
     * </code>
     *
     * @param Boolean $twos_compliment
     * @return String
     * @access public
     * @internal Converts a base-2**26 number to base-2**8
     */
    function toBytes($twos_compliment = false)
    {
        if ($twos_compliment) {
            $comparison = $this->compare(new Math_BigInteger());
            if ($comparison == 0) {
                return '';
            }

            $temp = $comparison < 0 ? $this->add(new Math_BigInteger(1)) : $this->_copy();
            $bytes = $temp->toBytes();

            if (empty($bytes)) { // eg. if the number we're trying to convert is -1
                $bytes = chr(0);
            }

            if (ord($bytes[0]) & 0x80) {
                $bytes = chr(0) . $bytes;
            }

            return $comparison < 0 ? ~$bytes : $bytes;
        }

        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                if (gmp_cmp($this->value, gmp_init(0)) == 0) {
                    return '';
                }

                $temp = gmp_strval(gmp_abs($this->value), 16);
                $temp = ( strlen($temp) & 1 ) ? '0' . $temp : $temp;

                return ltrim(pack('H*', $temp), chr(0));
            case MATH_BIGINTEGER_MODE_BCMATH:
                if ($this->value === '0') {
                    return '';
                }

                $value = '';
                $current = $this->value;

                if ($current[0] == '-') {
                    $current = substr($current, 1);
                }

                // we don't do four bytes at a time because then numbers larger than 1<<31 would be negative
                // two's complimented numbers, which would break chr.
                while (bccomp($current, '0') > 0) {
                    $temp = bcmod($current, 0x1000000);
                    $value = chr($temp >> 16) . chr($temp >> 8) . chr($temp) . $value;
                    $current = bcdiv($current, 0x1000000);
                }

                return ltrim($value, chr(0));
        }

        if (!count($this->value)) {
            return '';
        }

        $result = $this->_int2bytes($this->value[count($this->value) - 1]);

        $temp = $this->_copy();

        for ($i = count($temp->value) - 2; $i >= 0; $i--) {
            $temp->_base256_lshift($result, 26);
            $result = $result | str_pad($temp->_int2bytes($temp->value[$i]), strlen($result), chr(0), STR_PAD_LEFT);
        }

        return $result;
    }

    /**
     * Converts a BigInteger to a base-10 number.
     *
     * Here's a quick 'n dirty example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math_BigInteger('50');
     *
     *    echo $a->toString(); // outputs 50
     * ?>
     * </code>
     *
     * @return String
     * @access public
     * @internal Converts a base-2**26 number to base-10**7 (which is pretty much base-10)
     */
    function toString()
    {
        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                return gmp_strval($this->value);
            case MATH_BIGINTEGER_MODE_BCMATH:
                if ($this->value === '0') {
                    return '0';
                }

                return ltrim($this->value, '0');
        }

        if (!count($this->value)) {
            return '0';
        }

        $temp = $this->_copy();
        $temp->is_negative = false;

        $divisor = new Math_BigInteger();
        $divisor->value = array(10000000); // eg. 10**7
        while (count($temp->value)) {
            list($temp, $mod) = $temp->divide($divisor);
            $result = str_pad($this->_bytes2int($mod->toBytes()), 7, '0', STR_PAD_LEFT) . $result;
        }
        $result = ltrim($result, '0');

        if ($this->is_negative) {
            $result = '-' . $result;
        }

        return $result;
    }

    /**
     * Adds two BigIntegers.
     *
     * Here's a quick 'n dirty example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math_BigInteger('10');
     *    $b = new Math_BigInteger('20');
     *
     *    $c = $a->add($b);
     *
     *    echo $c->toString(); // outputs 30
     * ?>
     * </code>
     *
     * @param Math_BigInteger $y
     * @return Math_BigInteger
     * @access public
     * @internal Performs base-2**52 addition
     */
    function add($y)
    {
        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                $temp = new Math_BigInteger();
                $temp->value = gmp_add($this->value, $y->value);

                return $temp;
            case MATH_BIGINTEGER_MODE_BCMATH:
                $temp = new Math_BigInteger();
                $temp->value = bcadd($this->value, $y->value);

                return $temp;
        }

        // subtract, if appropriate
        if ( $this->is_negative != $y->is_negative ) {
            // is $y the negative number?
            $y_negative = $this->compare($y) > 0;

            $temp = $this->_copy();
            $y = $y->_copy();
            $temp->is_negative = $y->is_negative = false;

            $diff = $temp->compare($y);
            if ( !$diff ) {
                return new Math_BigInteger();
            }

            $temp = $temp->subtract($y);

            $temp->is_negative = ($diff > 0) ? !$y_negative : $y_negative;

            return $temp;
        }

        $result = new Math_BigInteger();
        $carry = 0;

        $size = max(count($this->value), count($y->value));
        $size+= $size & 1; // rounds $size to the nearest 2.

        $x = array_pad($this->value, $size,0);
        $y = array_pad($y->value, $size, 0);

        for ($i = 0; $i < $size - 1; $i+=2) {
            $sum = $x[$i + 1] * 0x4000000 + $x[$i] + $y[$i + 1] * 0x4000000 + $y[$i] + $carry;
            $carry = $sum >= 4503599627370496; // eg. floor($sum / 2**52); only possible values (in any base) are 0 and 1
            $sum = $carry ? $sum - 4503599627370496 : $sum;

            $temp = floor($sum / 0x4000000);

            $result->value[] = $sum - 0x4000000 * $temp; // eg. a faster alternative to fmod($sum, 0x4000000)
            $result->value[] = $temp;
        }

        if ($carry) {
            $result->value[] = $carry;
        }

        $result->is_negative = $this->is_negative;

        return $result->_normalize();
    }

    /**
     * Subtracts two BigIntegers.
     *
     * Here's a quick 'n dirty example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math_BigInteger('10');
     *    $b = new Math_BigInteger('20');
     *
     *    $c = $a->subtract($b);
     *
     *    echo $c->toString(); // outputs -10
     * ?>
     * </code>
     *
     * @param Math_BigInteger $y
     * @return Math_BigInteger
     * @access public
     * @internal Performs base-2**52 subtraction
     */
    function subtract($y)
    {
        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                $temp = new Math_BigInteger();
                $temp->value = gmp_sub($this->value, $y->value);

                return $temp;
            case MATH_BIGINTEGER_MODE_BCMATH:
                $temp = new Math_BigInteger();
                $temp->value = bcsub($this->value, $y->value);

                return $temp;
        }

        // add, if appropriate
        if ( $this->is_negative != $y->is_negative ) {
            $is_negative = $y->compare($this) > 0;

            $temp = $this->_copy();
            $y = $y->_copy();
            $temp->is_negative = $y->is_negative = false;

            $temp = $temp->add($y);

            $temp->is_negative = $is_negative;

            return $temp;
        }

        $diff = $this->compare($y);

        if ( !$diff ) {
            return new Math_BigInteger();
        }

        // switch $this and $y around, if appropriate.
        if ( (!$this->is_negative && $diff < 0) || ($this->is_negative && $diff > 0) ) {
            $is_negative = $y->is_negative;

            $temp = $this->_copy();
            $y = $y->_copy();
            $temp->is_negative = $y->is_negative = false;

            $temp = $y->subtract($temp);
            $temp->is_negative = !$is_negative;

            return $temp;
        }

        $result = new Math_BigInteger();
        $carry = 0;

        $size = max(count($this->value), count($y->value));
        $size+= $size % 2;

        $x = array_pad($this->value, $size, 0);
        $y = array_pad($y->value, $size, 0);

        for ($i = 0; $i < $size - 1;$i+=2) {
            $sum = $x[$i + 1] * 0x4000000 + $x[$i] - $y[$i + 1] * 0x4000000 - $y[$i] + $carry;
            $carry = $sum < 0 ? -1 : 0; // eg. floor($sum / 2**52); only possible values (in any base) are 0 and 1
            $sum = $carry ? $sum + 4503599627370496 : $sum;

            $temp = floor($sum / 0x4000000);

            $result->value[] = $sum - 0x4000000 * $temp;
            $result->value[] = $temp;
        }

        // $carry shouldn't be anything other than zero, at this point, since we already made sure that $this
        // was bigger than $y.

        $result->is_negative = $this->is_negative;

        return $result->_normalize();
    }

    /**
     * Multiplies two BigIntegers
     *
     * Here's a quick 'n dirty example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math_BigInteger('10');
     *    $b = new Math_BigInteger('20');
     *
     *    $c = $a->multiply($b);
     *
     *    echo $c->toString(); // outputs 200
     * ?>
     * </code>
     *
     * @param Math_BigInteger $x
     * @return Math_BigInteger
     * @access public
     * @internal Modeled after 'multiply' in MutableBigInteger.java.
     */
    function multiply($x)
    {
        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                $temp = new Math_BigInteger();
                $temp->value = gmp_mul($this->value, $x->value);

                return $temp;
            case MATH_BIGINTEGER_MODE_BCMATH:
                $temp = new Math_BigInteger();
                $temp->value = bcmul($this->value, $x->value);

                return $temp;
        }

        if ( !$this->compare($x) ) {
            return $this->_square();
        }

        $this_length = count($this->value);
        $x_length = count($x->value);

        if ( !$this_length || !$x_length ) { // a 0 is being multiplied
            return new Math_BigInteger();
        }

        $product = new Math_BigInteger();
        $product->value = $this->_array_repeat(0, $this_length + $x_length);

        // the following for loop could be removed if the for loop following it
        // (the one with nested for loops) initially set $i to 0, but
        // doing so would also make the result in one set of unnecessary adds,
        // since on the outermost loops first pass, $product->value[$k] is going
        // to always be 0

        $carry = 0;
        $i = 0;

        for ($j = 0, $k = $i; $j < $this_length; $j++, $k++) {
            $temp = $product->value[$k] + $this->value[$j] * $x->value[$i] + $carry;
            $carry = floor($temp / 0x4000000);
            $product->value[$k] = $temp - 0x4000000 * $carry;
        }

        $product->value[$k] = $carry;


        // the above for loop is what the previous comment was talking about.  the
        // following for loop is the "one with nested for loops"

        for ($i = 1; $i < $x_length; $i++) {
            $carry = 0;

            for ($j = 0, $k = $i; $j < $this_length; $j++, $k++) {
                $temp = $product->value[$k] + $this->value[$j] * $x->value[$i] + $carry;
                $carry = floor($temp / 0x4000000);
                $product->value[$k] = $temp - 0x4000000 * $carry;
            }

            $product->value[$k] = $carry;
        }

        $product->is_negative = $this->is_negative != $x->is_negative;

        return $product->_normalize();
    }

    /**
     * Squares a BigInteger
     *
     * Squaring can be done faster than multiplying a number by itself can be.  See
     * {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=7 HAC 14.2.4} /
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=141 MPM 5.3} for more information.
     *
     * @return Math_BigInteger
     * @access private
     */
    function _square()
    {
        if ( empty($this->value) ) {
            return new Math_BigInteger();
        }

        $max_index = count($this->value) - 1;

        $square = new Math_BigInteger();
        $square->value = $this->_array_repeat(0, 2 * $max_index);

        for ($i = 0; $i <= $max_index; $i++) {
            $temp = $square->value[2 * $i] + $this->value[$i] * $this->value[$i];
            $carry = floor($temp / 0x4000000);
            $square->value[2 * $i] = $temp - 0x4000000 * $carry;

            // note how we start from $i+1 instead of 0 as we do in multiplication.
            for ($j = $i + 1; $j <= $max_index; $j++) {
                $temp = $square->value[$i + $j] + 2 * $this->value[$j] * $this->value[$i] + $carry;
                $carry = floor($temp / 0x4000000);
                $square->value[$i + $j] = $temp - 0x4000000 * $carry;
            }

            // the following line can yield values larger 2**15.  at this point, PHP should switch
            // over to floats.
            $square->value[$i + $max_index + 1] = $carry;
        }

        return $square->_normalize();
    }

    /**
     * Divides two BigIntegers.
     *
     * Returns an array whose first element contains the quotient and whose second element contains the
     * "common residue".  If the remainder would be positive, the "common residue" and the remainder are the
     * same.  If the remainder would be negative, the "common residue" is equal to the sum of the remainder
     * and the divisor (basically, the "common residue" is the first positive modulo).
     *
     * Here's a quick 'n dirty example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math_BigInteger('10');
     *    $b = new Math_BigInteger('20');
     *
     *    list($quotient, $remainder) = $a->divide($b);
     *
     *    echo $quotient->toString(); // outputs 0
     *    echo "\r\n";
     *    echo $remainder->toString(); // outputs 10
     * ?>
     * </code>
     *
     * @param Math_BigInteger $y
     * @return Array
     * @access public
     * @internal This function is based off of {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=9 HAC 14.20}
     *    with a slight variation due to the fact that this script, initially, did not support negative numbers.  Now,
     *    it does, but I don't want to change that which already works.
     */
    function divide($y)
    {
        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                $quotient = new Math_BigInteger();
                $remainder = new Math_BigInteger();

                list($quotient->value, $remainder->value) = gmp_div_qr($this->value, $y->value);

                if (gmp_sign($remainder->value) < 0) {
                    $remainder->value = gmp_add($remainder->value, gmp_abs($y->value));
                }

                return array($quotient, $remainder);
            case MATH_BIGINTEGER_MODE_BCMATH:
                $quotient = new Math_BigInteger();
                $remainder = new Math_BigInteger();

                $quotient->value = bcdiv($this->value, $y->value);
                $remainder->value = bcmod($this->value, $y->value);

                if ($remainder->value[0] == '-') {
                    $remainder->value = bcadd($remainder->value, $y->value[0] == '-' ? substr($y->value, 1) : $y->value);
                }

                return array($quotient, $remainder);
        }

        $x = $this->_copy();
        $y = $y->_copy();

        $x_sign = $x->is_negative;
        $y_sign = $y->is_negative;

        $x->is_negative = $y->is_negative = false;

        $diff = $x->compare($y);

        if ( !$diff ) {
            $temp = new Math_BigInteger();
            $temp->value = array(1);
            $temp->is_negative = $x_sign != $y_sign;
            return array($temp, new Math_BigInteger());
        }

        if ( $diff < 0 ) {
            // if $x is negative, "add" $y.
            if ( $x_sign ) {
                $x = $y->subtract($x);
            }
            return array(new Math_BigInteger(), $x);
        }

        // normalize $x and $y as described in HAC 14.23 / 14.24
        // (incidently, i haven't been able to find a definitive example showing that this
        // results in worth-while speedup, but whatever)
        $msb = $y->value[count($y->value) - 1];
        for ($shift = 0; !($msb & 0x2000000); $shift++) {
            $msb <<= 1;
        }
        $x->_lshift($shift);
        $y->_lshift($shift);

        $x_max = count($x->value) - 1;
        $y_max = count($y->value) - 1;

        $quotient = new Math_BigInteger();
        $quotient->value = $this->_array_repeat(0, $x_max - $y_max + 1);

        // $temp = $y << ($x_max - $y_max-1) in base 2**26
        $temp = new Math_BigInteger();
        $temp->value = array_merge($this->_array_repeat(0, $x_max - $y_max), $y->value);

        while ( $x->compare($temp) >= 0 ) {
            // calculate the "common residue"
            $quotient->value[$x_max - $y_max]++;
            $x = $x->subtract($temp);
            $x_max = count($x->value) - 1;
        }

        for ($i = $x_max; $i >= $y_max + 1; $i--) {
            $x_value = array(
                $x->value[$i],
                ( $i > 0 ) ? $x->value[$i - 1] : 0,
                ( $i - 1 > 0 ) ? $x->value[$i - 2] : 0
            );
            $y_value = array(
                $y->value[$y_max],
                ( $y_max > 0 ) ? $y_max - 1 : 0
            );


            $q_index = $i - $y_max - 1;
            if ($x_value[0] == $y_value[0]) {
                $quotient->value[$q_index] = 0x3FFFFFF;
            } else {
                $quotient->value[$q_index] = floor(
                    ($x_value[0] * 0x4000000 + $x_value[1])
                    /
                    $y_value[0]
                );
            }

            $temp = new Math_BigInteger();
            $temp->value = array($y_value[1], $y_value[0]);

            $lhs = new Math_BigInteger();
            $lhs->value = array($quotient->value[$q_index]);
            $lhs = $lhs->multiply($temp);

            $rhs = new Math_BigInteger();
            $rhs->value = array($x_value[2], $x_value[1], $x_value[0]);
            
            while ( $lhs->compare($rhs) > 0 ) {
                $quotient->value[$q_index]--;

                $lhs = new Math_BigInteger();
                $lhs->value = array($quotient->value[$q_index]);
                $lhs = $lhs->multiply($temp);
            }

            $corrector = new Math_BigInteger();
            $temp = new Math_BigInteger();
            $corrector->value = $temp->value = $this->_array_repeat(0, $q_index);
            $temp->value[] = $quotient->value[$q_index];

            $temp = $temp->multiply($y);

            if ( $x->compare($temp) < 0 ) {
                $corrector->value[] = 1;
                $x = $x->add($corrector->multiply($y));
                $quotient->value[$q_index]--;
            }

            $x = $x->subtract($temp);
            $x_max = count($x->value) - 1;
        }

        // unnormalize the remainder
        $x->_rshift($shift);

        $quotient->is_negative = $x_sign != $y_sign;

        // calculate the "common residue", if appropriate
        if ( $x_sign ) {
            $y->_rshift($shift);
            $x = $y->subtract($x);
        }

        return array($quotient->_normalize(), $x);
    }

    /**
     * Performs modular exponentiation.
     *
     * Here's a quick 'n dirty example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math_BigInteger('10');
     *    $b = new Math_BigInteger('20');
     *    $c = new Math_BigInteger('30');
     *
     *    $c = $a->modPow($b, $c);
     *
     *    echo $c->toString(); // outputs 10
     * ?>
     * </code>
     *
     * @param Math_BigInteger $e
     * @param Math_BigInteger $n
     * @return Math_BigInteger
     * @access public
     * @internal The most naive approach to modular exponentiation has very unreasonable requirements, and
     *    and although the approach involving repeated squaring does vastly better, it, too, is impractical
     *    for our purposes.  The reason being that division - by far the most complicated and time-consuming
     *    of the basic operations (eg. +,-,*,/) - occurs multiple times within it.
     *
     *    Modular reductions resolve this issue.  Although an individual modular reduction takes more time
     *    then an individual division, when performed in succession (with the same modulo), they're a lot faster.
     *
     *    The two most commonly used modular reductions are Barrett and Montgomery reduction.  Montgomery reduction,
     *    although faster, only works when the gcd of the modulo and of the base being used is 1.  In RSA, when the
     *    base is a power of two, the modulo - a product of two primes - is always going to have a gcd of 1 (because
     *    the product of two odd numbers is odd), but what about when RSA isn't used?
     *
     *    In contrast, Barrett reduction has no such constraint.  As such, some bigint implementations perform a
     *    Barrett reduction after every operation in the modpow function.  Others perform Barrett reductions when the
     *    modulo is even and Montgomery reductions when the modulo is odd.  BigInteger.java's modPow method, however,
     *    uses a trick involving the Chinese Remainder Theorem to factor the even modulo into two numbers - one odd and
     *    the other, a power of two - and recombine them, later.  This is the method that this modPow function uses.
     *    {@link http://islab.oregonstate.edu/papers/j34monex.pdf Montgomery Reduction with Even Modulus} elaborates.
     */
    function modPow($e, $n)
    {
        $n = $n->abs();
        if ($e->compare(new Math_BigInteger()) < 0) {
            $e = $e->abs();

            $temp = $this->modInverse($n);
            if ($temp === false) {
                return false;
            }

            return $temp->modPow($e, $n);
        }

        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                $temp = new Math_BigInteger();
                $temp->value = gmp_powm($this->value, $e->value, $n->value);

                return $temp;
            case MATH_BIGINTEGER_MODE_BCMATH:
                $temp = new Math_BigInteger();
                $temp->value = bcpowmod($this->value, $e->value, $n->value);

                return $temp;
        }

        if ( empty($e->value) ) {
            $temp = new Math_BigInteger();
            $temp->value = array(1);
            return $temp;
        }

        if ( $e->value == array(1) ) {
            list(, $temp) = $this->divide($n);
            return $temp;
        }

        if ( $e->value == array(2) ) {
            $temp = $this->_square();
            list(, $temp) = $temp->divide($n);
            return $temp;
        }

        // is the modulo odd?
        if ( $n->value[0] & 1 ) {
            return $this->_slidingWindow($e, $n, MATH_BIGINTEGER_MONTGOMERY);
        }
        // if it's not, it's even

        // find the lowest set bit (eg. the max pow of 2 that divides $n)
        for ($i = 0; $i < count($n->value); $i++) {
            if ( $n->value[$i] ) {
                $temp = decbin($n->value[$i]);
                $j = strlen($temp) - strrpos($temp, '1') - 1;
                $j+= 26 * $i;
                break;
            }
        }
        // at this point, 2^$j * $n/(2^$j) == $n

        $mod1 = $n->_copy();
        $mod1->_rshift($j);
        $mod2 = new Math_BigInteger();
        $mod2->value = array(1);
        $mod2->_lshift($j);

        $part1 = ( $mod1->value != array(1) ) ? $this->_slidingWindow($e, $mod1, MATH_BIGINTEGER_MONTGOMERY) : new Math_BigInteger();
        $part2 = $this->_slidingWindow($e, $mod2, MATH_BIGINTEGER_POWEROF2);

        $y1 = $mod2->modInverse($mod1);
        $y2 = $mod1->modInverse($mod2);

        $result = $part1->multiply($mod2);
        $result = $result->multiply($y1);

        $temp = $part2->multiply($mod1);
        $temp = $temp->multiply($y2);

        $result = $result->add($temp);
        list(, $result) = $result->divide($n);

        return $result;
    }

    /**
     * Sliding Window k-ary Modular Exponentiation
     *
     * Based on {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=27 HAC 14.85} /
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=210 MPM 7.7}.  In a departure from those algorithims,
     * however, this function performs a modular reduction after every multiplication and squaring operation.
     * As such, this function has the same preconditions that the reductions being used do.
     *
     * @param Math_BigInteger $e
     * @param Math_BigInteger $n
     * @param Integer $mode
     * @return Math_BigInteger
     * @access private
     */
    function _slidingWindow($e, $n, $mode)
    {
        static $window_ranges = array(7, 25, 81, 241, 673, 1793); // from BigInteger.java's oddModPow function
        //static $window_ranges = array(0, 7, 36, 140, 450, 1303, 3529); // from MPM 7.3.1

        $e_length = count($e->value) - 1;
        $e_bits = decbin($e->value[$e_length]);
        for ($i = $e_length - 1; $i >= 0; $i--) {
            $e_bits.= str_pad(decbin($e->value[$i]), 26, '0', STR_PAD_LEFT);
        }
        $e_length = strlen($e_bits);

        // calculate the appropriate window size.
        // $window_size == 3 if $window_ranges is between 25 and 81, for example.
        for ($i = 0, $window_size = 1; $e_length > $window_ranges[$i] && $i < count($window_ranges); $window_size++, $i++);

        switch ($mode) {
            case MATH_BIGINTEGER_MONTGOMERY:
                $reduce = '_montgomery';
                $undo = '_undoMontgomery';
                break;
            case MATH_BIGINTEGER_BARRETT:
                $reduce = '_barrett';
                $undo = '_barrett';
                break;
            case MATH_BIGINTEGER_POWEROF2:
                $reduce = '_mod2';
                $undo = '_mod2';
                break;
            case MATH_BIGINTEGER_CLASSIC:
                $reduce = '_remainder';
                $undo = '_remainder';
                break;
            case MATH_BIGINTEGER_NONE:
                // ie. do no modular reduction.  useful if you want to just do pow as opposed to modPow.
                $reduce = '_copy';
                $undo = '_copy';
                break;
            default:
                // an invalid $mode was provided
        }

        // precompute $this^0 through $this^$window_size
        $powers = array();
        $powers[1] = $this->$undo($n);
        $powers[2] = $powers[1]->_square();
        $powers[2] = $powers[2]->$reduce($n);

        // we do every other number since substr($e_bits, $i, $j+1) (see below) is supposed to end
        // in a 1.  ie. it's supposed to be odd.
        $temp = 1 << ($window_size - 1);
        for ($i = 1; $i < $temp; $i++) {
            $powers[2 * $i + 1] = $powers[2 * $i - 1]->multiply($powers[2]);
            $powers[2 * $i + 1] = $powers[2 * $i + 1]->$reduce($n);
        }

        $result = new Math_BigInteger();
        $result->value = array(1);
        $result = $result->$undo($n);

        for ($i = 0; $i < $e_length; ) {
            if ( !$e_bits[$i] ) {
                $result = $result->_square();
                $result = $result->$reduce($n);
                $i++;
            } else {
                for ($j = $window_size - 1; $j >= 0; $j--) {
                    if ( $e_bits[$i + $j] ) {
                        break;
                    }
                }

                for ($k = 0; $k <= $j; $k++) {// eg. the length of substr($e_bits, $i, $j+1)
                    $result = $result->_square();
                    $result = $result->$reduce($n);
                }

                $result = $result->multiply($powers[bindec(substr($e_bits, $i, $j + 1))]);
                $result = $result->$reduce($n);

                $i+=$j + 1;
            }
        }

        $result = $result->$reduce($n);
        return $result->_normalize();
    }

    /**
     * Remainder
     *
     * A wrapper for the divide function.
     *
     * @see divide()
     * @see _slidingWindow()
     * @access private
     * @param Math_BigInteger
     * @return Math_BigInteger
     */
    function _remainder($n)
    {
        list(, $temp) = $this->divide($n);
        return $temp;
    }

    /**
     * Modulos for Powers of Two
     *
     * Calculates $x%$n, where $n = 2**$e, for some $e.  Since this is basically the same as doing $x & ($n-1),
     * we'll just use this function as a wrapper for doing that.
     *
     * @see _slidingWindow()
     * @access private
     * @param Math_BigInteger
     * @return Math_BigInteger
     */
    function _mod2($n)
    {
        $temp = new Math_BigInteger();
        $temp->value = array(1);
        return $this->bitwise_and($n->subtract($temp));
    }

    /**
     * Barrett Modular Reduction
     *
     * See {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=14 HAC 14.3.3} /
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=165 MPM 6.2.5} for more information.  Modified slightly,
     * so as not to require negative numbers (initially, this script didn't support negative numbers).
     *
     * @see _slidingWindow()
     * @access private
     * @param Math_BigInteger
     * @return Math_BigInteger
     */
    function _barrett($n)
    {
        static $cache;

        $n_length = count($n->value);

        if ( !isset($cache[MATH_BIGINTEGER_VARIABLE]) || $n->compare($cache[MATH_BIGINTEGER_VARIABLE]) ) {
            $cache[MATH_BIGINTEGER_VARIABLE] = $n;
            $temp = new Math_BigInteger();
            $temp->value = $this->_array_repeat(0, 2 * $n_length);
            $temp->value[] = 1;
            list($cache[MATH_BIGINTEGER_DATA], ) = $temp->divide($n);
        }

        $temp = new Math_BigInteger();
        $temp->value = array_slice($this->value, $n_length - 1);
        $temp = $temp->multiply($cache[MATH_BIGINTEGER_DATA]);
        $temp->value = array_slice($temp->value, $n_length + 1);

        $result = new Math_BigInteger();
        $result->value = array_slice($this->value, 0, $n_length + 1);
        $temp = $temp->multiply($n);
        $temp->value = array_slice($temp->value, 0, $n_length + 1);

        if ($result->compare($temp) < 0) {
            $corrector = new Math_BigInteger();
            $corrector->value = $this->_array_repeat(0, $n_length + 1);
            $corrector->value[] = 1;
            $result = $result->add($corrector);
        }

        $result = $result->subtract($temp);
        while ($result->compare($n) > 0) {
            $result = $result->subtract($n);
        }

        return $result;
    }

    /**
     * Montgomery Modular Reduction
     *
     * ($this->_montgomery($n))->_undoMontgomery($n) yields $x%$n.
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=170 MPM 6.3} provides insights on how this can be
     * improved upon (basically, by using the comba method).  gcd($n, 2) must be equal to one for this function
     * to work correctly.
     *
     * @see _undoMontgomery()
     * @see _slidingWindow()
     * @access private
     * @param Math_BigInteger
     * @return Math_BigInteger
     */
    function _montgomery($n)
    {
        static $cache;

        if ( !isset($cache[MATH_BIGINTEGER_VARIABLE]) || $n->compare($cache[MATH_BIGINTEGER_VARIABLE]) ) {
            $cache[MATH_BIGINTEGER_VARIABLE] = $n;
            $cache[MATH_BIGINTEGER_DATA] = $n->_modInverse67108864();
        }

        $result = $this->_copy();

        $n_length = count($n->value);

        for ($i = 0; $i < $n_length; $i++) {
            $temp = new Math_BigInteger();
            $temp->value = array(
                ($result->value[$i] * $cache[MATH_BIGINTEGER_DATA]) & 0x3FFFFFF
            );
            $temp = $temp->multiply($n);
            $temp->value = array_merge($this->_array_repeat(0, $i), $temp->value);
            $result = $result->add($temp);
        }

        $result->value = array_slice($result->value, $n_length);

        if ($result->compare($n) >= 0) {
            $result = $result->subtract($n);
        }

        return $result->_normalize();
    }

    /**
     * Undo Montgomery Modular Reduction
     *
     * @see _montgomery()
     * @see _slidingWindow()
     * @access private
     * @param Math_BigInteger
     * @return Math_BigInteger
     */
    function _undoMontgomery($n)
    {
        $temp = new Math_BigInteger();
        $temp->value = array_merge($this->_array_repeat(0, count($n->value)), $this->value);
        list(, $temp) = $temp->divide($n);
        return $temp->_normalize();
    }

    /**
     * Modular Inverse of a number mod 2**26 (eg. 67108864)
     *
     * Based off of the bnpInvDigit function implemented and justified in the following URL:
     *
     * {@link http://www-cs-students.stanford.edu/~tjw/jsbn/jsbn.js}
     *
     * The following URL provides more info:
     *
     * {@link http://groups.google.com/group/sci.crypt/msg/7a137205c1be7d85}
     *
     * As for why we do all the bitmasking...  strange things can happen when converting from flots to ints. For
     * instance, on some computers, var_dump((int) -4294967297) yields int(-1) and on others, it yields 
     * int(-2147483648).  To avoid problems stemming from this, we use bitmasks to guarantee that ints aren't
     * auto-converted to floats.  The outermost bitmask is present because without it, there's no guarantee that
     * the "residue" returned would be the so-called "common residue".  We use fmod, in the last step, because the
     * maximum possible $x is 26 bits and the maximum $result is 16 bits.  Thus, we have to be able to handle up to
     * 40 bits, which only 64-bit floating points will support.
     *
     * Thanks to Pedro Gimeno Fortea for input!
     *
     * @see _montgomery()
     * @access private
     * @return Integer
     */
    function _modInverse67108864() // 2**26 == 67108864
    {
        $x = -$this->value[0];
        $result = $x & 0x3; // x**-1 mod 2**2
        $result = ($result * (2 - $x * $result)) & 0xF; // x**-1 mod 2**4
        $result = ($result * (2 - ($x & 0xFF) * $result))  & 0xFF; // x**-1 mod 2**8
        $result = ($result * ((2 - ($x & 0xFFFF) * $result) & 0xFFFF)) & 0xFFFF; // x**-1 mod 2**16
        $result = fmod($result * (2 - fmod($x * $result, 0x4000000)), 0x4000000); // x**-1 mod 2**26
        return $result & 0x3FFFFFF;
    }

    /**
     * Calculates modular inverses.
     *
     * Here's a quick 'n dirty example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math_BigInteger(30);
     *    $b = new Math_BigInteger(17);
     *
     *    $c = $a->modInverse($b);
     *
     *    echo $c->toString(); // outputs 4
     * ?>
     * </code>
     *
     * @param Math_BigInteger $n
     * @return mixed false, if no modular inverse exists, Math_BigInteger, otherwise.
     * @access public
     * @internal Calculates the modular inverse of $this mod $n using the binary xGCD algorithim described in
     *    {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=19 HAC 14.61}.  As the text above 14.61 notes,
     *    the more traditional algorithim requires "relatively costly multiple-precision divisions".  See
     *    {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=21 HAC 14.64} for more information.
     */
    function modInverse($n)
    {
        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                $temp = new Math_BigInteger();
                $temp->value = gmp_invert($this->value, $n->value);

                return ( $temp->value === false ) ? false : $temp;
            case MATH_BIGINTEGER_MODE_BCMATH:
                // it might be faster to use the binary xGCD algorithim here, as well, but (1) that algorithim works
                // best when the base is a power of 2 and (2) i don't think it'd make much difference, anyway.  as is,
                // the basic extended euclidean algorithim is what we're using.

                // if $x is less than 0, the first character of $x is a '-', so we'll remove it.  we can do this because
                // $x mod $n == $x mod -$n.
                $n = (bccomp($n->value, '0') < 0) ? substr($n->value, 1) : $n->value;

                if (bccomp($this->value,'0') < 0) {
                    $negated_this = new Math_BigInteger();
                    $negated_this->value = substr($this->value, 1);

                    $temp = $negated_this->modInverse(new Math_BigInteger($n));

                    if ($temp === false) {
                        return false;
                    }

                    $temp->value = bcsub($n, $temp->value);

                    return $temp;
                }

                $u = $this->value;
                $v = $n;

                $a = '1';
                $c = '0';

                while (true) {
                    $q = bcdiv($u, $v);
                    $temp = $u;
                    $u = $v;
                    $v = bcsub($temp, bcmul($v, $q));

                    if (bccomp($v, '0') == 0) {
                        break;
                    }

                    $temp = $a;
                    $a = $c;
                    $c = bcsub($temp, bcmul($c, $q));
                }

                $temp = new Math_BigInteger();
                $temp->value = (bccomp($c, '0') < 0) ? bcadd($c, $n) : $c;

                // $u contains the gcd of $this and $n
                return (bccomp($u,'1') == 0) ? $temp : false;
        }

        // if $this and $n are even, return false.
        if ( !($this->value[0]&1) && !($n->value[0]&1) ) {
            return false;
        }

        $n = $n->_copy();
        $n->is_negative = false;

        if ($this->compare(new Math_BigInteger()) < 0) {
            // is_negative is currently true.  since we need it to be false, we'll just set it to false, temporarily,
            // and reset it as true, later.
            $this->is_negative = false;

            $temp = $this->modInverse($n);

            if ($temp === false) {
                return false;
            }

            $temp = $n->subtract($temp);

            $this->is_negative = true;

            return $temp;
        }

        $u = $n->_copy();
        $x = $this;
        //list(, $x) = $this->divide($n);
        $v = $x->_copy();

        $a = new Math_BigInteger();
        $b = new Math_BigInteger();
        $c = new Math_BigInteger();
        $d = new Math_BigInteger();

        $a->value = $d->value = array(1);

        while ( !empty($u->value) ) {
            while ( !($u->value[0] & 1) ) {
                $u->_rshift(1);
                if ( ($a->value[0] & 1) || ($b->value[0] & 1) ) {
                    $a = $a->add($x);
                    $b = $b->subtract($n);
                }
                $a->_rshift(1);
                $b->_rshift(1);
            }

            while ( !($v->value[0] & 1) ) {
                $v->_rshift(1);
                if ( ($c->value[0] & 1) || ($d->value[0] & 1) ) {
                    $c = $c->add($x);
                    $d = $d->subtract($n);
                }
                $c->_rshift(1);
                $d->_rshift(1);
            }

            if ($u->compare($v) >= 0) {
                $u = $u->subtract($v);
                $a = $a->subtract($c);
                $b = $b->subtract($d);
            } else {
                $v = $v->subtract($u);
                $c = $c->subtract($a);
                $d = $d->subtract($b);
            }

            $u->_normalize();
        }

        // at this point, $v == gcd($this, $n).  if it's not equal to 1, no modular inverse exists.
        if ( $v->value != array(1) ) {
            return false;
        }

        $d = ($d->compare(new Math_BigInteger()) < 0) ? $d->add($n) : $d;

        return ($this->is_negative) ? $n->subtract($d) : $d;
    }

    /**
     * Absolute value.
     *
     * @return Math_BigInteger
     * @access public
     */
    function abs()
    {
        $temp = new Math_BigInteger();

        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                $temp->value = gmp_abs($this->value);
                break;
            case MATH_BIGINTEGER_MODE_BCMATH:
                $temp->value = (bccomp($this->value, '0') < 0) ? substr($this->value, 1) : $this->value;
                break;
            default:
                $temp->value = $this->value;
        }

        return $temp;
    }

    /**
     * Compares two numbers.
     *
     * @param Math_BigInteger $x
     * @return Integer < 0 if $this is less than $x; > 0 if $this is greater than $x, and 0 if they are equal.
     * @access public
     * @internal Could return $this->sub($x), but that's not as fast as what we do do.
     */
    function compare($x)
    {
        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                return gmp_cmp($this->value, $x->value);
            case MATH_BIGINTEGER_MODE_BCMATH:
                return bccomp($this->value, $x->value);
        }

        $this->_normalize();
        $x->_normalize();

        if ( $this->is_negative != $x->is_negative ) {
            return ( !$this->is_negative && $x->is_negative ) ? 1 : -1;
        }

        $result = $this->is_negative ? -1 : 1;

        if ( count($this->value) != count($x->value) ) {
            return ( count($this->value) > count($x->value) ) ? $result : -$result;
        }

        for ($i = count($this->value) - 1; $i >= 0; $i--) {
            if ($this->value[$i] != $x->value[$i]) {
                return ( $this->value[$i] > $x->value[$i] ) ? $result : -$result;
            }
        }

        return 0;
    }

    /**
     * Returns a copy of $this
     *
     * PHP5 passes objects by reference while PHP4 passes by value.  As such, we need a function to guarantee
     * that all objects are passed by value, when appropriate.  More information can be found here:
     *
     * {@link http://www.php.net/manual/en/language.oop5.basic.php#51624}
     *
     * @access private
     * @return Math_BigInteger
     */
    function _copy()
    {
        $temp = new Math_BigInteger();
        $temp->value = $this->value;
        $temp->is_negative = $this->is_negative;
        return $temp;
    }

    /**
     * Logical And
     *
     * @param Math_BigInteger $x
     * @access public
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     * @return Math_BigInteger
     */
    function bitwise_and($x)
    {
        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                $temp = new Math_BigInteger();
                $temp->value = gmp_and($this->value, $x->value);

                return $temp;
            case MATH_BIGINTEGER_MODE_BCMATH:
                return new Math_BigInteger($this->toBytes() & $x->toBytes(), 256);
        }

        $result = new Math_BigInteger();

        $x_length = count($x->value);
        for ($i = 0; $i < $x_length; $i++) {
            $result->value[] = $this->value[$i] & $x->value[$i];
        }

        return $result->_normalize();
    }

    /**
     * Logical Or
     *
     * @param Math_BigInteger $x
     * @access public
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     * @return Math_BigInteger
     */
    function bitwise_or($x)
    {
        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                $temp = new Math_BigInteger();
                $temp->value = gmp_or($this->value, $x->value);

                return $temp;
            case MATH_BIGINTEGER_MODE_BCMATH:
                return new Math_BigInteger($this->toBytes() | $x->toBytes(), 256);
        }

        $result = $this->_copy();

        $x_length = count($x->value);
        for ($i = 0; $i < $x_length; $i++) {
            $result->value[$i] = $this->value[$i] | $x->value[$i];
        }

        return $result->_normalize();
    }

    /**
     * Logical Exclusive-Or
     *
     * @param Math_BigInteger $x
     * @access public
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     * @return Math_BigInteger
     */
    function bitwise_xor($x)
    {
        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                $temp = new Math_BigInteger();
                $temp->value = gmp_xor($this->value, $x->value);

                return $temp;
            case MATH_BIGINTEGER_MODE_BCMATH:
                return new Math_BigInteger($this->toBytes() ^ $x->toBytes(), 256);
        }

        $result = $this->_copy();

        $x_length = count($x->value);
        for ($i = 0; $i < $x_length; $i++) {
            $result->value[$i] = $this->value[$i] ^ $x->value[$i];
        }

        return $result->_normalize();
    }

    /**
     * Logical Not
     *
     * Although integers can be converted to and from various bases with relative ease, there is one piece
     * of information that is lost during such conversions.  The number of leading zeros that number had
     * or should have in any given base.  Per that, if you convert 1 from decimal to binary, there's no
     * way to know just how many leading zero's there should be.  In truth, there could be any number.
     *
     * Normally, the number of leading zero's is unimportant.  When doing "not", however, it is.  The "not"
     * of 1 on an 8-bit representation of 1 is 1111 1110.  The "not" of 1 on a 16-bit representation of 1 is
     * 1111 1111 1111 1110.  When doing it on a number that's preceeded by an infinite number of zero's, it's
     * infinite.
     *
     * This function assumes that there are no leading zero's - that the bit-representation being used is
     * equal to the minimum number of required bits, unless otherwise specified in the optional parameter,
     * where the optional parameter represents the bit-representation being used.  If the specified
     * bit-representation is smaller than the minimum number of bits required to represent the number, the
     * latter will be used as the bit-representation.
     *
     * @param $bits Integer
     * @access public
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     * @return Math_BigInteger
     */
    function bitwise_not($bits = -1)
    {
        // calculuate "not" without regard to $bits
        $temp = ~$this->toBytes();
        $msb = decbin(ord($temp[0]));
        $msb = substr($msb, strpos($msb, '0'));
        $temp[0] = chr(bindec($msb));

        // see if we need to add extra leading 1's
        $current_bits = strlen($msb) + 8 * strlen($temp) - 8;
        $new_bits = $bits - $current_bits;
        if ($new_bits <= 0) {
            return new Math_BigInteger($temp, 256);
        }

        // generate as many leading 1's as we need to.
        $leading_ones = chr((1 << ($new_bits & 0x7)) - 1) . str_repeat(chr(0xFF), $new_bits >> 3);
        $this->_base256_lshift($leading_ones, $current_bits);

        $temp = str_pad($temp, ceil($bits / 8), chr(0), STR_PAD_LEFT);

        return new Math_BigInteger($leading_ones | $temp, 256);
    }

    /**
     * Logical Right Shift
     *
     * Shifts BigInteger's by $shift bits, effectively dividing by 2**$shift.
     *
     * @param Integer $shift
     * @return Math_BigInteger
     * @access public
     * @internal The only version that yields any speed increases is the internal version.
     */
    function bitwise_rightShift($shift)
    {
        $temp = new Math_BigInteger();

        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                static $two;

                if (empty($two)) {
                    $two = gmp_init('2');
                }

                $temp->value = gmp_div_q($this->value, gmp_pow($two, $shift));

                break;
            case MATH_BIGINTEGER_MODE_BCMATH:

                $temp->value = bcdiv($this->value, bcpow('2', $shift));

                break;
            default: // could just replace _lshift with this, but then all _lshift() calls would need to be rewritten
                     // and I don't want to do that...
                $temp->value = $this->value;
                $temp->_rshift($shift);
        }

        return $temp;
    }

    /**
     * Logical Left Shift
     *
     * Shifts BigInteger's by $shift bits, effectively multiplying by 2**$shift.
     *
     * @param Integer $shift
     * @return Math_BigInteger
     * @access public
     * @internal The only version that yields any speed increases is the internal version.
     */
    function bitwise_leftShift($shift)
    {
        $temp = new Math_BigInteger();

        switch ( MATH_BIGINTEGER_MODE ) {
            case MATH_BIGINTEGER_MODE_GMP:
                static $two;

                if (empty($two)) {
                    $two = gmp_init('2');
                }

                $temp->value = gmp_mul($this->value, gmp_pow($two, $shift));

                break;
            case MATH_BIGINTEGER_MODE_BCMATH:
                $temp->value = bcmul($this->value, bcpow('2', $shift));

                break;
            default: // could just replace _rshift with this, but then all _lshift() calls would need to be rewritten
                     // and I don't want to do that...
                $temp->value = $this->value;
                $temp->_lshift($shift);
        }

        return $temp;
    }

    /**
     * Generate a random number
     *
     * $generator should be the name of a random number generating function whose first parameter is the minimum
     * value and whose second parameter is the maximum value.  If this function needs to be seeded, it should be
     * done before this function is called.
     *
     * @param optional Integer $min
     * @param optional Integer $max
     * @param optional String $generator
     * @return Math_BigInteger
     * @access public
     */
    function random($min = false, $max = false, $generator = 'mt_rand')
    {
        if ($min === false) {
            $min = new Math_BigInteger(0);
        }

        if ($max === false) {
            $max = new Math_BigInteger(0x7FFFFFFF);
        }

        $compare = $max->compare($min);

        if (!$compare) {
            return $min;
        } else if ($compare < 0) {
            // if $min is bigger then $max, swap $min and $max
            $temp = $max;
            $max = $min;
            $min = $temp;
        }

        $max = $max->subtract($min);
        $max = ltrim($max->toBytes(), chr(0));
        $size = strlen($max) - 1;

        $bytes = $size & 3;
        for ($i = 0; $i < $bytes; $i++) {
            $random.= chr($generator(0, 255));
        }

        $blocks = $size >> 2;
        for ($i = 0; $i < $blocks; $i++) {
            $random.= pack('N', $generator(-2147483648, 0x7FFFFFFF));
        }

        $temp = new Math_BigInteger($random, 256);
        if ($temp->compare(new Math_BigInteger(substr($max, 1), 256)) > 0) {
            $random = chr($generator(0, ord($max[0]) - 1)) . $random;
        } else {
            $random = chr($generator(0, ord($max[0])    )) . $random;
        }

        $random = new Math_BigInteger($random, 256);

        return $random->add($min);
    }

    /**
     * Logical Left Shift
     *
     * Shifts BigInteger's by $shift bits.
     *
     * @param Integer $shift
     * @access private
     */
    function _lshift($shift)
    {
        if ( $shift == 0 ) {
            return;
        }

        $num_digits = floor($shift / 26);
        $shift %= 26;
        $shift = 1 << $shift;

        $carry = 0;

        for ($i = 0; $i < count($this->value); $i++) {
            $temp = $this->value[$i] * $shift + $carry;
            $carry = floor($temp / 0x4000000);
            $this->value[$i] = $temp - $carry * 0x4000000;
        }

        if ( $carry ) {
            $this->value[] = $carry;
        }

        while ($num_digits--) {
            array_unshift($this->value, 0);
        }
    }

    /**
     * Logical Right Shift
     *
     * Shifts BigInteger's by $shift bits.
     *
     * @param Integer $shift
     * @access private
     */
    function _rshift($shift)
    {
        if ($shift == 0) {
            $this->_normalize();
        }

        $num_digits = floor($shift / 26);
        $shift %= 26;
        $carry_shift = 26 - $shift;
        $carry_mask = (1 << $shift) - 1;

        if ( $num_digits ) {
            $this->value = array_slice($this->value, $num_digits);
        }

        $carry = 0;

        for ($i = count($this->value) - 1; $i >= 0; $i--) {
            $temp = $this->value[$i] >> $shift | $carry;
            $carry = ($this->value[$i] & $carry_mask) << $carry_shift;
            $this->value[$i] = $temp;
        }

        $this->_normalize();
    }

    /**
     * Normalize
     *
     * Deletes leading zeros.
     *
     * @see divide()
     * @return Math_BigInteger
     * @access private
     */
    function _normalize()
    {
        if ( !count($this->value) ) {
            return $this;
        }

        for ($i=count($this->value) - 1; $i >= 0; $i--) {
            if ( $this->value[$i] ) {
                break;
            }
            unset($this->value[$i]);
        }

        return $this;
    }

    /**
     * Array Repeat
     *
     * @param $input Array
     * @param $multiplier mixed
     * @return Array
     * @access private
     */
    function _array_repeat($input, $multiplier)
    {
        return ($multiplier) ? array_fill(0, $multiplier, $input) : array();
    }

    /**
     * Logical Left Shift
     *
     * Shifts binary strings $shift bits, essentially multiplying by 2**$shift.
     *
     * @param $x String
     * @param $shift Integer
     * @return String
     * @access private
     */
    function _base256_lshift(&$x, $shift)
    {
        if ($shift == 0) {
            return;
        }

        $num_bytes = $shift >> 3; // eg. floor($shift/8)
        $shift &= 7; // eg. $shift % 8

        $carry = 0;
        for ($i = strlen($x) - 1; $i >= 0; $i--) {
            $temp = ord($x[$i]) << $shift | $carry;
            $x[$i] = chr($temp);
            $carry = $temp >> 8;
        }
        $carry = ($carry != 0) ? chr($carry) : '';
        $x = $carry . $x . str_repeat(chr(0), $num_bytes);
    }

    /**
     * Logical Right Shift
     *
     * Shifts binary strings $shift bits, essentially dividing by 2**$shift and returning the remainder.
     *
     * @param $x String
     * @param $shift Integer
     * @return String
     * @access private
     */
    function _base256_rshift(&$x, $shift)
    {
        if ($shift == 0) {
            $x = ltrim($x, chr(0));
            return '';
        }

        $num_bytes = $shift >> 3; // eg. floor($shift/8)
        $shift &= 7; // eg. $shift % 8

        $remainder = '';
        if ($num_bytes) {
            $start = $num_bytes > strlen($x) ? -strlen($x) : -$num_bytes;
            $remainder = substr($x, $start);
            $x = substr($x, 0, -$num_bytes);
        }

        $carry = 0;
        $carry_shift = 8 - $shift;
        for ($i = 0; $i < strlen($x); $i++) {
            $temp = (ord($x[$i]) >> $shift) | $carry;
            $carry = (ord($x[$i]) << $carry_shift) & 0xFF;
            $x[$i] = chr($temp);
        }
        $x = ltrim($x, chr(0));

        $remainder = chr($carry >> $carry_shift) . $remainder;

        return ltrim($remainder, chr(0));
    }

    // one quirk about how the following functions are implemented is that PHP defines N to be an unsigned long
    // at 32-bits, while java's longs are 64-bits.

    /**
     * Converts 32-bit integers to bytes.
     *
     * @param Integer $x
     * @return String
     * @access private
     */
    function _int2bytes($x)
    {
        return ltrim(pack('N', $x), chr(0));
    }

    /**
     * Converts bytes to 32-bit integers
     *
     * @param String $x
     * @return Integer
     * @access private
     */
    function _bytes2int($x)
    {
        $temp = unpack('Nint', str_pad($x, 4, chr(0), STR_PAD_LEFT));
        return $temp['int'];
    }
}

// vim: ts=4:sw=4:et:
// vim6: fdl=1:
?>