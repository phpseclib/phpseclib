<?php

/**
 * Pure-PHP arbitrary precision integer arithmetic library.
 *
 * Supports base-2, base-10, base-16, and base-256 numbers.  Uses the GMP or BCMath extensions, if available,
 * and an internal implementation, otherwise.
 *
 * PHP versions 4 and 5
 *
 * {@internal (all DocBlock comments regarding implementation - such as the one that follows - refer to the 
 * {@link BigInteger::MODE_INTERNAL BigInteger::MODE_INTERNAL} mode)
 *
 * Math\BigInteger uses base-2**26 to perform operations such as multiplication and division and
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
 * Numbers are stored in {@link http://en.wikipedia.org/wiki/Endianness little endian} format.  ie.
 * (new Math\BigInteger(pow(2, 26)))->value = array(0, 1)
 *
 * Useful resources are as follows:
 *
 *  - {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf Handbook of Applied Cryptography (HAC)}
 *  - {@link http://math.libtomcrypt.com/files/tommath.pdf Multi-Precision Math (MPM)}
 *  - Java's BigInteger classes.  See /j2se/src/share/classes/java/math in jdk-1_5_0-src-jrl.zip
 *
 * Here's an example of how to use this library:
 * <code>
 * <?php
 *    include('Math/BigInteger.php');
 *
 *    $a = new Math\BigInteger(2);
 *    $b = new Math\BigInteger(3);
 *
 *    $c = $a->add($b);
 *
 *    echo $c->toString(); // outputs 5
 * ?>
 * </code>
 *
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @category  Math
 * @package   Math\BigInteger
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright MMVI Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://pear.php.net/package/Math\BigInteger
 */

namespace phpseclib\Math;

use phpseclib\Crypt\Random;

/**
 * Pure-PHP arbitrary precision integer arithmetic library. Supports base-2, base-10, base-16, and base-256
 * numbers.
 *
 * @package Math\BigInteger
 * @author  Jim Wigginton <terrafrost@php.net>
 * @version 1.0.0RC4
 * @access  public
 */
class BigInteger
{
    /**
     * @see Math\BigInteger::_montgomery()
     * @see Math\BigInteger::_prepMontgomery()
     */
    const MONTGOMERY = 0;
    
    /**
     * @see Math\BigInteger::_barrett()
     */
    const BARRETT = 1;
    
    /**
     * @see Math\BigInteger::_mod2()
     */
    const POWEROF2 = 2;
    
    /**
     * @see Math\BigInteger::_remainder()
     */
    const CLASSIC = 3;
    
    /**
     * @see Math\BigInteger::__clone()
     */
    const NONE = 4;
    
    /**
     * $result[VALUE] contains the value.
     */
    const VALUE = 0;
    
    /**
     * $result[SIGN] contains the sign.
     */
    const SIGN = 1;
    
    /**
     * Cache constants
     *
     * $cache[VARIABLE] tells us whether or not the cached data is still valid.
     */
    const VARIABLE = 0;
    
    /**
     * $cache[DATA] contains the cached data.
     */
    const DATA = 1;
    
    /**
     * To use the pure-PHP implementation
     */
    const MODE_INTERNAL = 1;
    
    /**
     * To use the BCMath library
     *
     * (if enabled; otherwise, the internal implementation will be used)
     */
    const MODE_BCMATH = 2;
    
    /**
     * To use the GMP library
     *
     * (if present; otherwise, either the BCMath or the internal implementation will be used)
     */
    const MODE_GMP = 3;
    
    /**
     * Karatsuba Cutoff
     *
     * At what point do we switch between Karatsuba multiplication and schoolbook long multiplication?
     *
     * @access private
     */
    const KARATSUBA_CUTOFF = 25;
    
    /**
     * Holds the BigInteger's value.
     *
     * @var Array
     * @access private
     */
    private $value;

    /**
     * Holds the BigInteger's magnitude.
     *
     * @var Boolean
     * @access private
     */
    private $is_negative = false;

    /**
     * Random number generator function
     *
     * @see setRandomGenerator()
     * @access private
     */
    private $generator = 'mt_rand';

    /**
     * Precision
     *
     * @see setPrecision()
     * @access private
     */
    private $precision = -1;

    /**
     * Precision Bitmask
     *
     * @see setPrecision()
     * @access private
     */
    private $bitmask = false;

    /**
     * Mode independent value used for serialization.
     *
     * If the bcmath or gmp extensions are installed $this->value will be a non-serializable resource, hence the need for 
     * a variable that'll be serializable regardless of whether or not extensions are being used.  Unlike $this->value,
     * however, $this->hex is only calculated when $this->__sleep() is called.
     *
     * @see __sleep()
     * @see __wakeup()
     * @var String
     * @access private
     */
    private $hex;
    
    /* Moved these variables from global scope to class variables
     * They are not constant value since they are set at runtime and
     * therefore should not be defined via define or const.
     */
    private $mode = null;
    private $base = null;
    private $baseFull = null;
    private $maxDigit = null;
    private $msb = null;
    private $max10 = null;
    private $max10Len = null;
    private $maxDigit2 = null;
    
    /**
     * Converts base-2, base-10, base-16, and binary strings (base-256) to BigIntegers.
     *
     * If the second parameter - $base - is negative, then it will be assumed that the number's are encoded using
     * two's compliment.  The sole exception to this is -10, which is treated the same as 10 is.
     *
     * Here's an example:
     * <code>
     * &lt;?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger('0x32', 16); // 50 in base-16
     *
     *    echo $a->toString(); // outputs 50
     * ?&gt;
     * </code>
     *
     * @param optional $x base-10 number or base-$base number if $base set.
     * @param optional integer $base
     * @return Math\BigInteger
     * @access public
     */
    public function __construct($x = 0, $base = 10)
    {
        if ($this->mode === null) {
            switch (true) {
                case extension_loaded('gmp'):
                    $this->mode = BigInteger::MODE_GMP;
                    break;
                case extension_loaded('bcmath'):
                    $this->mode = BigInteger::MODE_BCMATH;
                    break;
                default:
                    $this->mode = BigInteger::MODE_INTERNAL;
            }
        }

        if (!defined('PHP_INT_SIZE')) {
            define('PHP_INT_SIZE', 4);
        }

        if ($this->base === null && $this->mode == BigInteger::MODE_INTERNAL) {
            switch (PHP_INT_SIZE) {
                case 8: // use 64-bit integers if int size is 8 bytes
                    $this->base = 31;
                    $this->baseFull = 0x80000000;
                    $this->maxDigit = 0x7FFFFFFF;
                    $this->msb = 0x40000000;
                    // 10**9 is the closest we can get to 2**31 without passing it
                    $this->max10 = 1000000000;
                    $this->max10Len = 9;
                    // the largest digit that may be used in addition / subtraction
                    $this->maxDigit2 = pow(2, 62);
                    break;
                //case 4: // use 64-bit floats if int size is 4 bytes
                default:
                    $this->base = 26;
                    $this->baseFull = 0x4000000;
                    $this->maxDigit = 0x3FFFFFF;
                    $this->msb = 0x2000000;
                    // 10**7 is the closest to 2**26 without passing it
                    $this->max10 = 10000000;
                    $this->max10Len = 7;
                    // the largest digit that may be used in addition / subtraction
                    // we do pow(2, 52) instead of using 4503599627370496 directly because some
                    // PHP installations will truncate 4503599627370496.
                    $this->maxDigit2 = pow(2, 52);
            }
        }

        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                if (is_resource($x) && get_resource_type($x) == 'GMP integer') {
                    $this->value = $x;
                    return;
                }
                $this->value = gmp_init(0);
                break;
            case BigInteger::MODE_BCMATH:
                $this->value = '0';
                break;
            default:
                $this->value = array();
        }

        // '0' counts as empty() but when the base is 256 '0' is equal to ord('0') or 48
        // '0' is the only value like this per http://php.net/empty
        if (empty($x) && (abs($base) != 256 || $x !== '0')) {
            return;
        }

        switch ($base) {
            case -256:
                if (ord($x[0]) & 0x80) {
                    $x = ~$x;
                    $this->is_negative = true;
                }
            case  256:
                switch ( $this->mode ) {
                    case BigInteger::MODE_GMP:
                        $sign = $this->is_negative ? '-' : '';
                        $this->value = gmp_init($sign . '0x' . bin2hex($x));
                        break;
                    case BigInteger::MODE_BCMATH:
                        // round $len to the nearest 4 (thanks, DavidMJ!)
                        $len = (strlen($x) + 3) & 0xFFFFFFFC;

                        $x = str_pad($x, $len, chr(0), STR_PAD_LEFT);

                        for ($i = 0; $i < $len; $i+= 4) {
                            $this->value = bcmul($this->value, '4294967296', 0); // 4294967296 == 2**32
                            $this->value = bcadd($this->value, 0x1000000 * ord($x[$i]) + ((ord($x[$i + 1]) << 16) | (ord($x[$i + 2]) << 8) | ord($x[$i + 3])), 0);
                        }

                        if ($this->is_negative) {
                            $this->value = '-' . $this->value;
                        }

                        break;
                    // converts a base-2**8 (big endian / msb) number to base-2**26 (little endian / lsb)
                    default:
                        while (strlen($x)) {
                            $this->value[] = $this->_bytes2int($this->_base256_rshift($x, $this->base));
                        }
                }

                if ($this->is_negative) {
                    if ($this->mode != BigInteger::MODE_INTERNAL) {
                        $this->is_negative = false;
                    }
                    $temp = $this->add(new BigInteger('-1'));
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

                switch ( $this->mode ) {
                    case BigInteger::MODE_GMP:
                        $temp = $this->is_negative ? '-0x' . $x : '0x' . $x;
                        $this->value = gmp_init($temp);
                        $this->is_negative = false;
                        break;
                    case BigInteger::MODE_BCMATH:
                        $x = ( strlen($x) & 1 ) ? '0' . $x : $x;
                        $temp = new BigInteger(pack('H*', $x), 256);
                        $this->value = $this->is_negative ? '-' . $temp->value : $temp->value;
                        $this->is_negative = false;
                        break;
                    default:
                        $x = ( strlen($x) & 1 ) ? '0' . $x : $x;
                        $temp = new BigInteger(pack('H*', $x), 256);
                        $this->value = $temp->value;
                }

                if ($is_negative) {
                    $temp = $this->add(new BigInteger('-1'));
                    $this->value = $temp->value;
                }
                break;
            case  10:
            case -10:
                // (?<!^)(?:-).*: find any -'s that aren't at the beginning and then any characters that follow that
                // (?<=^|-)0*: find any 0's that are preceded by the start of the string or by a - (ie. octals)
                // [^-0-9].*: find any non-numeric characters and then any characters that follow that
                $x = preg_replace('#(?<!^)(?:-).*|(?<=^|-)0*|[^-0-9].*#', '', $x);

                switch ( $this->mode ) {
                    case BigInteger::MODE_GMP:
                        $this->value = gmp_init($x);
                        break;
                    case BigInteger::MODE_BCMATH:
                        // explicitly casting $x to a string is necessary, here, since doing $x[0] on -1 yields different
                        // results then doing it on '-1' does (modInverse does $x[0])
                        $this->value = $x === '-' ? '0' : (string) $x;
                        break;
                    default:
                        $temp = new BigInteger();

                        $multiplier = new BigInteger();
                        $multiplier->value = array($this->max10);

                        if ($x[0] == '-') {
                            $this->is_negative = true;
                            $x = substr($x, 1);
                        }

                        $x = str_pad($x, strlen($x) + (($this->max10Len - 1) * strlen($x)) % $this->max10Len, 0, STR_PAD_LEFT);
                        while (strlen($x)) {
                            $temp = $temp->multiply($multiplier);
                            $temp = $temp->add(new BigInteger($this->_int2bytes(substr($x, 0, $this->max10Len)), 256));
                            $x = substr($x, $this->max10Len);
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

                $temp = new BigInteger($str, 8 * $base); // ie. either -16 or +16
                $this->value = $temp->value;
                $this->is_negative = $temp->is_negative;

                break;
            default:
                // base not supported, so we'll let $this == 0
        }
    }
    
    public static function isOpenSslEnabled() {
        if (function_exists('openssl_public_encrypt')) {
            return false;
        }
        
        // some versions of XAMPP have mismatched versions of OpenSSL which causes it not to work
        ob_start();
        phpinfo();
        $content = ob_get_contents();
        ob_end_clean();

        preg_match_all('#OpenSSL (Header|Library) Version(.*)#im', $content, $matches);

        $versions = array();
        if (!empty($matches[1])) {
            for ($i = 0; $i < count($matches[1]); $i++) {
                $versions[$matches[1][$i]] = trim(str_replace('=>', '', strip_tags($matches[2][$i])));
            }
        }

        // it doesn't appear that OpenSSL versions were reported upon until PHP 5.3+
        if (!isset($versions['Header']) || !isset($versions['Library']) || $versions['Header'] == $versions['Library']) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Converts a BigInteger to a byte string (eg. base-256).
     *
     * Negative numbers are saved as positive numbers, unless $twos_compliment is set to true, at which point, they're
     * saved as two's compliment.
     *
     * Here's an example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger('65');
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
    public function toBytes($twos_compliment = false)
    {
        if ($twos_compliment) {
            $comparison = $this->compare(new BigInteger());
            if ($comparison == 0) {
                return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
            }

            $temp = $comparison < 0 ? $this->add(new BigInteger(1)) : $this->copy();
            $bytes = $temp->toBytes();

            if (empty($bytes)) { // eg. if the number we're trying to convert is -1
                $bytes = chr(0);
            }

            if (ord($bytes[0]) & 0x80) {
                $bytes = chr(0) . $bytes;
            }

            return $comparison < 0 ? ~$bytes : $bytes;
        }

        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                if (gmp_cmp($this->value, gmp_init(0)) == 0) {
                    return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
                }

                $temp = gmp_strval(gmp_abs($this->value), 16);
                $temp = ( strlen($temp) & 1 ) ? '0' . $temp : $temp;
                $temp = pack('H*', $temp);

                return $this->precision > 0 ?
                    substr(str_pad($temp, $this->precision >> 3, chr(0), STR_PAD_LEFT), -($this->precision >> 3)) :
                    ltrim($temp, chr(0));
            case BigInteger::MODE_BCMATH:
                if ($this->value === '0') {
                    return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
                }

                $value = '';
                $current = $this->value;

                if ($current[0] == '-') {
                    $current = substr($current, 1);
                }

                while (bccomp($current, '0', 0) > 0) {
                    $temp = bcmod($current, '16777216');
                    $value = chr($temp >> 16) . chr($temp >> 8) . chr($temp) . $value;
                    $current = bcdiv($current, '16777216', 0);
                }

                return $this->precision > 0 ?
                    substr(str_pad($value, $this->precision >> 3, chr(0), STR_PAD_LEFT), -($this->precision >> 3)) :
                    ltrim($value, chr(0));
        }

        if (!count($this->value)) {
            return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
        }
        $result = $this->_int2bytes($this->value[count($this->value) - 1]);

        $temp = $this->copy();

        for ($i = count($temp->value) - 2; $i >= 0; --$i) {
            $temp->_base256_lshift($result, $this->base);
            $result = $result | str_pad($temp->_int2bytes($temp->value[$i]), strlen($result), chr(0), STR_PAD_LEFT);
        }

        return $this->precision > 0 ?
            str_pad(substr($result, -(($this->precision + 7) >> 3)), ($this->precision + 7) >> 3, chr(0), STR_PAD_LEFT) :
            $result;
    }

    /**
     * Converts a BigInteger to a hex string (eg. base-16)).
     *
     * Negative numbers are saved as positive numbers, unless $twos_compliment is set to true, at which point, they're
     * saved as two's compliment.
     *
     * Here's an example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger('65');
     *
     *    echo $a->toHex(); // outputs '41'
     * ?>
     * </code>
     *
     * @param Boolean $twos_compliment
     * @return String
     * @access public
     * @internal Converts a base-2**26 number to base-2**8
     */
    public function toHex($twos_compliment = false)
    {
        return bin2hex($this->toBytes($twos_compliment));
    }

    /**
     * Converts a BigInteger to a bit string (eg. base-2).
     *
     * Negative numbers are saved as positive numbers, unless $twos_compliment is set to true, at which point, they're
     * saved as two's compliment.
     *
     * Here's an example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger('65');
     *
     *    echo $a->toBits(); // outputs '1000001'
     * ?>
     * </code>
     *
     * @param Boolean $twos_compliment
     * @return String
     * @access public
     * @internal Converts a base-2**26 number to base-2**2
     */
    public function toBits($twos_compliment = false)
    {
        $hex = $this->toHex($twos_compliment);
        $bits = '';
        for ($i = strlen($hex) - 8, $start = strlen($hex) & 7; $i >= $start; $i-=8) {
            $bits = str_pad(decbin(hexdec(substr($hex, $i, 8))), 32, '0', STR_PAD_LEFT) . $bits;
        }
        if ($start) { // hexdec('') == 0
            $bits = str_pad(decbin(hexdec(substr($hex, 0, $start))), 8, '0', STR_PAD_LEFT) . $bits;
        }
        $result = $this->precision > 0 ? substr($bits, -$this->precision) : ltrim($bits, '0');

        if ($twos_compliment && $this->compare(new BigInteger()) > 0 && $this->precision <= 0) {
            return '0' . $result;
        }

        return $result;
    }

    /**
     * Converts a BigInteger to a base-10 number.
     *
     * Here's an example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger('50');
     *
     *    echo $a->toString(); // outputs 50
     * ?>
     * </code>
     *
     * @return String
     * @access public
     * @internal Converts a base-2**26 number to base-10**7 (which is pretty much base-10)
     */
    public function toString()
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                return gmp_strval($this->value);
            case BigInteger::MODE_BCMATH:
                if ($this->value === '0') {
                    return '0';
                }

                return ltrim($this->value, '0');
        }

        if (!count($this->value)) {
            return '0';
        }

        $temp = $this->copy();
        $temp->is_negative = false;

        $divisor = new BigInteger();
        $divisor->value = array($this->max10);
        $result = '';
        while (count($temp->value)) {
            list($temp, $mod) = $temp->divide($divisor);
            $result = str_pad(isset($mod->value[0]) ? $mod->value[0] : '', $this->max10Len, '0', STR_PAD_LEFT) . $result;
        }
        $result = ltrim($result, '0');
        if (empty($result)) {
            $result = '0';
        }

        if ($this->is_negative) {
            $result = '-' . $result;
        }

        return $result;
    }

    /**
     * Copy an object
     *
     * PHP5 passes objects by reference while PHP4 passes by value.  As such, we need a function to guarantee
     * that all objects are passed by value, when appropriate.  More information can be found here:
     *
     * {@link http://php.net/language.oop5.basic#51624}
     *
     * @access public
     * @see __clone()
     * @return Math\BigInteger
     */
    public function copy()
    {
        $temp = new BigInteger();
        $temp->value = $this->value;
        $temp->is_negative = $this->is_negative;
        $temp->generator = $this->generator;
        $temp->precision = $this->precision;
        $temp->bitmask = $this->bitmask;
        return $temp;
    }

    /**
     *  __toString() magic method
     *
     * Will be called, automatically, if you're supporting just PHP5.  If you're supporting PHP4, you'll need to call
     * toString().
     *
     * @access public
     * @internal Implemented per a suggestion by Techie-Michael - thanks!
     */
    public function __toString()
    {
        return $this->toString();
    }

    /**
     * __clone() magic method
     *
     * Although you can call Math\BigInteger::__toString() directly in PHP5, you cannot call Math\BigInteger::__clone()
     * directly in PHP5.  You can in PHP4 since it's not a magic method, but in PHP5, you have to call it by using the PHP5
     * only syntax of $y = clone $x.  As such, if you're trying to write an application that works on both PHP4 and PHP5,
     * call Math\BigInteger::copy(), instead.
     *
     * @access public
     * @see copy()
     * @return Math\BigInteger
     */
    public function __clone()
    {
        return $this->copy();
    }

    /**
     *  __sleep() magic method
     *
     * Will be called, automatically, when serialize() is called on a Math\BigInteger object.
     *
     * @see __wakeup()
     * @access public
     */
    public function __sleep()
    {
        $this->hex = $this->toHex(true);
        $vars = array('hex');
        if ($this->generator != 'mt_rand') {
            $vars[] = 'generator';
        }
        if ($this->precision > 0) {
            $vars[] = 'precision';
        }
        return $vars;
        
    }

    /**
     *  __wakeup() magic method
     *
     * Will be called, automatically, when unserialize() is called on a Math\BigInteger object.
     *
     * @see __sleep()
     * @access public
     */
    public function __wakeup()
    {
        $temp = new BigInteger($this->hex, -16);
        $this->value = $temp->value;
        $this->is_negative = $temp->is_negative;
        $this->setRandomGenerator($this->generator);
        if ($this->precision > 0) {
            // recalculate $this->bitmask
            $this->setPrecision($this->precision);
        }
    }

    /**
     * Adds two BigIntegers.
     *
     * Here's an example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger('10');
     *    $b = new Math\BigInteger('20');
     *
     *    $c = $a->add($b);
     *
     *    echo $c->toString(); // outputs 30
     * ?>
     * </code>
     *
     * @param Math\BigInteger $y
     * @return Math\BigInteger
     * @access public
     * @internal Performs base-2**52 addition
     */
    public function add($y)
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                $temp = new BigInteger();
                $temp->value = gmp_add($this->value, $y->value);

                return $this->_normalize($temp);
            case BigInteger::MODE_BCMATH:
                $temp = new BigInteger();
                $temp->value = bcadd($this->value, $y->value, 0);

                return $this->_normalize($temp);
        }

        $temp = $this->_add($this->value, $this->is_negative, $y->value, $y->is_negative);

        $result = new BigInteger();
        $result->value = $temp[BigInteger::VALUE];
        $result->is_negative = $temp[BigInteger::SIGN];

        return $this->_normalize($result);
    }

    /**
     * Performs addition.
     *
     * @param Array $x_value
     * @param Boolean $x_negative
     * @param Array $y_value
     * @param Boolean $y_negative
     * @return Array
     * @access private
     */
   private function _add($x_value, $x_negative, $y_value, $y_negative)
    {
        $x_size = count($x_value);
        $y_size = count($y_value);

        if ($x_size == 0) {
            return array(
                BigInteger::VALUE => $y_value,
                BigInteger::SIGN => $y_negative
            );
        } else if ($y_size == 0) {
            return array(
                BigInteger::VALUE => $x_value,
                BigInteger::SIGN => $x_negative
            );
        }

        // subtract, if appropriate
        if ( $x_negative != $y_negative ) {
            if ( $x_value == $y_value ) {
                return array(
                    BigInteger::VALUE => array(),
                    BigInteger::SIGN => false
                );
            }

            $temp = $this->_subtract($x_value, false, $y_value, false);
            $temp[BigInteger::SIGN] = $this->_compare($x_value, false, $y_value, false) > 0 ?
                                          $x_negative : $y_negative;

            return $temp;
        }

        if ($x_size < $y_size) {
            $size = $x_size;
            $value = $y_value;
        } else {
            $size = $y_size;
            $value = $x_value;
        }

        $value[] = 0; // just in case the carry adds an extra digit

        $carry = 0;
        for ($i = 0, $j = 1; $j < $size; $i+=2, $j+=2) {
            $sum = $x_value[$j] * $this->baseFull + $x_value[$i] + $y_value[$j] * $this->baseFull + $y_value[$i] + $carry;
            $carry = $sum >= $this->maxDigit2; // eg. floor($sum / 2**52); only possible values (in any base) are 0 and 1
            $sum = $carry ? $sum - $this->maxDigit2 : $sum;

            $temp = (int) ($sum / $this->baseFull);

            $value[$i] = (int) ($sum - $this->baseFull * $temp); // eg. a faster alternative to fmod($sum, 0x4000000)
            $value[$j] = $temp;
        }

        if ($j == $size) { // ie. if $y_size is odd
            $sum = $x_value[$i] + $y_value[$i] + $carry;
            $carry = $sum >= $this->baseFull;
            $value[$i] = $carry ? $sum - $this->baseFull : $sum;
            ++$i; // ie. let $i = $j since we've just done $value[$i]
        }

        if ($carry) {
            for (; $value[$i] == $this->maxDigit; ++$i) {
                $value[$i] = 0;
            }
            ++$value[$i];
        }

        return array(
            BigInteger::VALUE => $this->_trim($value),
            BigInteger::SIGN => $x_negative
        );
    }

    /**
     * Subtracts two BigIntegers.
     *
     * Here's an example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger('10');
     *    $b = new Math\BigInteger('20');
     *
     *    $c = $a->subtract($b);
     *
     *    echo $c->toString(); // outputs -10
     * ?>
     * </code>
     *
     * @param Math\BigInteger $y
     * @return Math\BigInteger
     * @access public
     * @internal Performs base-2**52 subtraction
     */
    public function subtract($y)
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                $temp = new BigInteger();
                $temp->value = gmp_sub($this->value, $y->value);

                return $this->_normalize($temp);
            case BigInteger::MODE_BCMATH:
                $temp = new BigInteger();
                $temp->value = bcsub($this->value, $y->value, 0);

                return $this->_normalize($temp);
        }

        $temp = $this->_subtract($this->value, $this->is_negative, $y->value, $y->is_negative);

        $result = new BigInteger();
        $result->value = $temp[BigInteger::VALUE];
        $result->is_negative = $temp[BigInteger::SIGN];

        return $this->_normalize($result);
    }

    /**
     * Performs subtraction.
     *
     * @param Array $x_value
     * @param Boolean $x_negative
     * @param Array $y_value
     * @param Boolean $y_negative
     * @return Array
     * @access private
     */
    private function _subtract($x_value, $x_negative, $y_value, $y_negative)
    {
        $x_size = count($x_value);
        $y_size = count($y_value);

        if ($x_size == 0) {
            return array(
                BigInteger::VALUE => $y_value,
                BigInteger::SIGN => !$y_negative
            );
        } else if ($y_size == 0) {
            return array(
                BigInteger::VALUE => $x_value,
                BigInteger::SIGN => $x_negative
            );
        }

        // add, if appropriate (ie. -$x - +$y or +$x - -$y)
        if ( $x_negative != $y_negative ) {
            $temp = $this->_add($x_value, false, $y_value, false);
            $temp[BigInteger::SIGN] = $x_negative;

            return $temp;
        }

        $diff = $this->_compare($x_value, $x_negative, $y_value, $y_negative);

        if ( !$diff ) {
            return array(
                BigInteger::VALUE => array(),
                BigInteger::SIGN => false
            );
        }

        // switch $x and $y around, if appropriate.
        if ( (!$x_negative && $diff < 0) || ($x_negative && $diff > 0) ) {
            $temp = $x_value;
            $x_value = $y_value;
            $y_value = $temp;

            $x_negative = !$x_negative;

            $x_size = count($x_value);
            $y_size = count($y_value);
        }

        // at this point, $x_value should be at least as big as - if not bigger than - $y_value

        $carry = 0;
        for ($i = 0, $j = 1; $j < $y_size; $i+=2, $j+=2) {
            $sum = $x_value[$j] * $this->baseFull + $x_value[$i] - $y_value[$j] * $this->baseFull - $y_value[$i] - $carry;
            $carry = $sum < 0; // eg. floor($sum / 2**52); only possible values (in any base) are 0 and 1
            $sum = $carry ? $sum + $this->maxDigit2 : $sum;

            $temp = (int) ($sum / $this->baseFull);

            $x_value[$i] = (int) ($sum - $this->baseFull * $temp);
            $x_value[$j] = $temp;
        }

        if ($j == $y_size) { // ie. if $y_size is odd
            $sum = $x_value[$i] - $y_value[$i] - $carry;
            $carry = $sum < 0;
            $x_value[$i] = $carry ? $sum + $this->baseFull : $sum;
            ++$i;
        }

        if ($carry) {
            for (; !$x_value[$i]; ++$i) {
                $x_value[$i] = $this->maxDigit;
            }
            --$x_value[$i];
        }

        return array(
            BigInteger::VALUE => $this->_trim($x_value),
            BigInteger::SIGN => $x_negative
        );
    }

    /**
     * Multiplies two BigIntegers
     *
     * Here's an example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger('10');
     *    $b = new Math\BigInteger('20');
     *
     *    $c = $a->multiply($b);
     *
     *    echo $c->toString(); // outputs 200
     * ?>
     * </code>
     *
     * @param Math\BigInteger $x
     * @return Math\BigInteger
     * @access public
     */
    public function multiply($x)
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                $temp = new BigInteger();
                $temp->value = gmp_mul($this->value, $x->value);

                return $this->_normalize($temp);
            case BigInteger::MODE_BCMATH:
                $temp = new BigInteger();
                $temp->value = bcmul($this->value, $x->value, 0);

                return $this->_normalize($temp);
        }

        $temp = $this->_multiply($this->value, $this->is_negative, $x->value, $x->is_negative);

        $product = new BigInteger();
        $product->value = $temp[BigInteger::VALUE];
        $product->is_negative = $temp[BigInteger::SIGN];

        return $this->_normalize($product);
    }

    /**
     * Performs multiplication.
     *
     * @param Array $x_value
     * @param Boolean $x_negative
     * @param Array $y_value
     * @param Boolean $y_negative
     * @return Array
     * @access private
     */
    private function _multiply($x_value, $x_negative, $y_value, $y_negative)
    {
        //if ( $x_value == $y_value ) {
        //    return array(
        //        BigInteger::VALUE => $this->_square($x_value),
        //        BigInteger::SIGN => $x_sign != $y_value
        //    );
        //}

        $x_length = count($x_value);
        $y_length = count($y_value);

        if ( !$x_length || !$y_length ) { // a 0 is being multiplied
            return array(
                BigInteger::VALUE => array(),
                BigInteger::SIGN => false
            );
        }

        return array(
            BigInteger::VALUE => min($x_length, $y_length) < 2 * BigInteger::KARATSUBA_CUTOFF ?
                $this->_trim($this->_regularMultiply($x_value, $y_value)) :
                $this->_trim($this->_karatsuba($x_value, $y_value)),
            BigInteger::SIGN => $x_negative != $y_negative
        );
    }

    /**
     * Performs long multiplication on two BigIntegers
     *
     * Modeled after 'multiply' in MutableBigInteger.java.
     *
     * @param Array $x_value
     * @param Array $y_value
     * @return Array
     * @access private
     */
    private function _regularMultiply($x_value, $y_value)
    {
        $x_length = count($x_value);
        $y_length = count($y_value);

        if ( !$x_length || !$y_length ) { // a 0 is being multiplied
            return array();
        }

        if ( $x_length < $y_length ) {
            $temp = $x_value;
            $x_value = $y_value;
            $y_value = $temp;

            $x_length = count($x_value);
            $y_length = count($y_value);
        }

        $product_value = $this->_array_repeat(0, $x_length + $y_length);

        // the following for loop could be removed if the for loop following it
        // (the one with nested for loops) initially set $i to 0, but
        // doing so would also make the result in one set of unnecessary adds,
        // since on the outermost loops first pass, $product->value[$k] is going
        // to always be 0

        $carry = 0;

        for ($j = 0; $j < $x_length; ++$j) { // ie. $i = 0
            $temp = $x_value[$j] * $y_value[0] + $carry; // $product_value[$k] == 0
            $carry = (int) ($temp / $this->baseFull);
            $product_value[$j] = (int) ($temp - $this->baseFull * $carry);
        }

        $product_value[$j] = $carry;

        // the above for loop is what the previous comment was talking about.  the
        // following for loop is the "one with nested for loops"
        for ($i = 1; $i < $y_length; ++$i) {
            $carry = 0;

            for ($j = 0, $k = $i; $j < $x_length; ++$j, ++$k) {
                $temp = $product_value[$k] + $x_value[$j] * $y_value[$i] + $carry;
                $carry = (int) ($temp / $this->baseFull);
                $product_value[$k] = (int) ($temp - $this->baseFull * $carry);
            }

            $product_value[$k] = $carry;
        }

        return $product_value;
    }

    /**
     * Performs Karatsuba multiplication on two BigIntegers
     *
     * See {@link http://en.wikipedia.org/wiki/Karatsuba_algorithm Karatsuba algorithm} and
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=120 MPM 5.2.3}.
     *
     * @param Array $x_value
     * @param Array $y_value
     * @return Array
     * @access private
     */
    private function _karatsuba($x_value, $y_value)
    {
        $m = min(count($x_value) >> 1, count($y_value) >> 1);

        if ($m < BigInteger::KARATSUBA_CUTOFF) {
            return $this->_regularMultiply($x_value, $y_value);
        }

        $x1 = array_slice($x_value, $m);
        $x0 = array_slice($x_value, 0, $m);
        $y1 = array_slice($y_value, $m);
        $y0 = array_slice($y_value, 0, $m);

        $z2 = $this->_karatsuba($x1, $y1);
        $z0 = $this->_karatsuba($x0, $y0);

        $z1 = $this->_add($x1, false, $x0, false);
        $temp = $this->_add($y1, false, $y0, false);
        $z1 = $this->_karatsuba($z1[BigInteger::VALUE], $temp[BigInteger::VALUE]);
        $temp = $this->_add($z2, false, $z0, false);
        $z1 = $this->_subtract($z1, false, $temp[BigInteger::VALUE], false);

        $z2 = array_merge(array_fill(0, 2 * $m, 0), $z2);
        $z1[BigInteger::VALUE] = array_merge(array_fill(0, $m, 0), $z1[BigInteger::VALUE]);

        $xy = $this->_add($z2, false, $z1[BigInteger::VALUE], $z1[BigInteger::SIGN]);
        $xy = $this->_add($xy[BigInteger::VALUE], $xy[BigInteger::SIGN], $z0, false);

        return $xy[BigInteger::VALUE];
    }

    /**
     * Performs squaring
     *
     * @param Array $x
     * @return Array
     * @access private
     */
    private function _square($x = false)
    {
        return count($x) < 2 * BigInteger::KARATSUBA_CUTOFF ?
            $this->_trim($this->_baseSquare($x)) :
            $this->_trim($this->_karatsubaSquare($x));
    }

    /**
     * Performs traditional squaring on two BigIntegers
     *
     * Squaring can be done faster than multiplying a number by itself can be.  See
     * {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=7 HAC 14.2.4} /
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=141 MPM 5.3} for more information.
     *
     * @param Array $value
     * @return Array
     * @access private
     */
    private function _baseSquare($value)
    {
        if ( empty($value) ) {
            return array();
        }
        $square_value = $this->_array_repeat(0, 2 * count($value));

        for ($i = 0, $max_index = count($value) - 1; $i <= $max_index; ++$i) {
            $i2 = $i << 1;

            $temp = $square_value[$i2] + $value[$i] * $value[$i];
            $carry = (int) ($temp / $this->baseFull);
            $square_value[$i2] = (int) ($temp - $this->baseFull * $carry);

            // note how we start from $i+1 instead of 0 as we do in multiplication.
            for ($j = $i + 1, $k = $i2 + 1; $j <= $max_index; ++$j, ++$k) {
                $temp = $square_value[$k] + 2 * $value[$j] * $value[$i] + $carry;
                $carry = (int) ($temp / $this->baseFull);
                $square_value[$k] = (int) ($temp - $this->baseFull * $carry);
            }

            // the following line can yield values larger 2**15.  at this point, PHP should switch
            // over to floats.
            $square_value[$i + $max_index + 1] = $carry;
        }

        return $square_value;
    }

    /**
     * Performs Karatsuba "squaring" on two BigIntegers
     *
     * See {@link http://en.wikipedia.org/wiki/Karatsuba_algorithm Karatsuba algorithm} and
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=151 MPM 5.3.4}.
     *
     * @param Array $value
     * @return Array
     * @access private
     */
    private function _karatsubaSquare($value)
    {
        $m = count($value) >> 1;

        if ($m < BigInteger::KARATSUBA_CUTOFF) {
            return $this->_baseSquare($value);
        }

        $x1 = array_slice($value, $m);
        $x0 = array_slice($value, 0, $m);

        $z2 = $this->_karatsubaSquare($x1);
        $z0 = $this->_karatsubaSquare($x0);

        $z1 = $this->_add($x1, false, $x0, false);
        $z1 = $this->_karatsubaSquare($z1[BigInteger::VALUE]);
        $temp = $this->_add($z2, false, $z0, false);
        $z1 = $this->_subtract($z1, false, $temp[BigInteger::VALUE], false);

        $z2 = array_merge(array_fill(0, 2 * $m, 0), $z2);
        $z1[BigInteger::VALUE] = array_merge(array_fill(0, $m, 0), $z1[BigInteger::VALUE]);

        $xx = $this->_add($z2, false, $z1[BigInteger::VALUE], $z1[BigInteger::SIGN]);
        $xx = $this->_add($xx[BigInteger::VALUE], $xx[BigInteger::SIGN], $z0, false);

        return $xx[BigInteger::VALUE];
    }

    /**
     * Divides two BigIntegers.
     *
     * Returns an array whose first element contains the quotient and whose second element contains the
     * "common residue".  If the remainder would be positive, the "common residue" and the remainder are the
     * same.  If the remainder would be negative, the "common residue" is equal to the sum of the remainder
     * and the divisor (basically, the "common residue" is the first positive modulo).
     *
     * Here's an example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger('10');
     *    $b = new Math\BigInteger('20');
     *
     *    list($quotient, $remainder) = $a->divide($b);
     *
     *    echo $quotient->toString(); // outputs 0
     *    echo "\r\n";
     *    echo $remainder->toString(); // outputs 10
     * ?>
     * </code>
     *
     * @param Math\BigInteger $y
     * @return Array
     * @access public
     * @internal This function is based off of {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=9 HAC 14.20}.
     */
    public function divide($y)
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                $quotient = new BigInteger();
                $remainder = new BigInteger();

                list($quotient->value, $remainder->value) = gmp_div_qr($this->value, $y->value);

                if (gmp_sign($remainder->value) < 0) {
                    $remainder->value = gmp_add($remainder->value, gmp_abs($y->value));
                }

                return array($this->_normalize($quotient), $this->_normalize($remainder));
            case BigInteger::MODE_BCMATH:
                $quotient = new BigInteger();
                $remainder = new BigInteger();
                
                $quotient->value = bcdiv($this->value, $y->value, 0);
                $remainder->value = bcmod($this->value, $y->value);

                if ($remainder->value[0] == '-') {
                    $remainder->value = bcadd($remainder->value, $y->value[0] == '-' ? substr($y->value, 1) : $y->value, 0);
                }

                return array($this->_normalize($quotient), $this->_normalize($remainder));
        }

        if (count($y->value) == 1) {
            list($q, $r) = $this->_divide_digit($this->value, $y->value[0]);
            $quotient = new BigInteger();
            $remainder = new BigInteger();
            $quotient->value = $q;
            $remainder->value = array($r);
            $quotient->is_negative = $this->is_negative != $y->is_negative;
            return array($this->_normalize($quotient), $this->_normalize($remainder));
        }

        static $zero;
        if ( !isset($zero) ) {
            $zero = new BigInteger();
        }

        $x = $this->copy();
        $y = $y->copy();

        $x_sign = $x->is_negative;
        $y_sign = $y->is_negative;

        $x->is_negative = $y->is_negative = false;

        $diff = $x->compare($y);

        if ( !$diff ) {
            $temp = new BigInteger();
            $temp->value = array(1);
            $temp->is_negative = $x_sign != $y_sign;
            return array($this->_normalize($temp), $this->_normalize(new BigInteger()));
        }

        if ( $diff < 0 ) {
            // if $x is negative, "add" $y.
            if ( $x_sign ) {
                $x = $y->subtract($x);
            }
            return array($this->_normalize(new BigInteger()), $this->_normalize($x));
        }

        // normalize $x and $y as described in HAC 14.23 / 14.24
        $msb = $y->value[count($y->value) - 1];
        for ($shift = 0; !($msb & $this->msb); ++$shift) {
            $msb <<= 1;
        }
        $x->_lshift($shift);
        $y->_lshift($shift);
        $y_value = &$y->value;

        $x_max = count($x->value) - 1;
        $y_max = count($y->value) - 1;

        $quotient = new BigInteger();
        $quotient_value = &$quotient->value;
        $quotient_value = $this->_array_repeat(0, $x_max - $y_max + 1);

        static $temp, $lhs, $rhs;
        if (!isset($temp)) {
            $temp = new BigInteger();
            $lhs =  new BigInteger();
            $rhs =  new BigInteger();
        }
        $temp_value = &$temp->value;
        $rhs_value =  &$rhs->value;

        // $temp = $y << ($x_max - $y_max-1) in base 2**26
        $temp_value = array_merge($this->_array_repeat(0, $x_max - $y_max), $y_value);

        while ( $x->compare($temp) >= 0 ) {
            // calculate the "common residue"
            ++$quotient_value[$x_max - $y_max];
            $x = $x->subtract($temp);
            $x_max = count($x->value) - 1;
        }

        for ($i = $x_max; $i >= $y_max + 1; --$i) {
            $x_value = &$x->value;
            $x_window = array(
                isset($x_value[$i]) ? $x_value[$i] : 0,
                isset($x_value[$i - 1]) ? $x_value[$i - 1] : 0,
                isset($x_value[$i - 2]) ? $x_value[$i - 2] : 0
            );
            $y_window = array(
                $y_value[$y_max],
                ( $y_max > 0 ) ? $y_value[$y_max - 1] : 0
            );

            $q_index = $i - $y_max - 1;
            if ($x_window[0] == $y_window[0]) {
                $quotient_value[$q_index] = $this->maxDigit;
            } else {
                $quotient_value[$q_index] = (int) (
                    ($x_window[0] * $this->baseFull + $x_window[1])
                    /
                    $y_window[0]
                );
            }

            $temp_value = array($y_window[1], $y_window[0]);

            $lhs->value = array($quotient_value[$q_index]);
            $lhs = $lhs->multiply($temp);

            $rhs_value = array($x_window[2], $x_window[1], $x_window[0]);

            while ( $lhs->compare($rhs) > 0 ) {
                --$quotient_value[$q_index];

                $lhs->value = array($quotient_value[$q_index]);
                $lhs = $lhs->multiply($temp);
            }

            $adjust = $this->_array_repeat(0, $q_index);
            $temp_value = array($quotient_value[$q_index]);
            $temp = $temp->multiply($y);
            $temp_value = &$temp->value;
            $temp_value = array_merge($adjust, $temp_value);

            $x = $x->subtract($temp);

            if ($x->compare($zero) < 0) {
                $temp_value = array_merge($adjust, $y_value);
                $x = $x->add($temp);

                --$quotient_value[$q_index];
            }

            $x_max = count($x_value) - 1;
        }

        // unnormalize the remainder
        $x->_rshift($shift);

        $quotient->is_negative = $x_sign != $y_sign;

        // calculate the "common residue", if appropriate
        if ( $x_sign ) {
            $y->_rshift($shift);
            $x = $y->subtract($x);
        }

        return array($this->_normalize($quotient), $this->_normalize($x));
    }

    /**
     * Divides a BigInteger by a regular integer
     *
     * abc / x = a00 / x + b0 / x + c / x
     *
     * @param Array $dividend
     * @param Array $divisor
     * @return Array
     * @access private
     */
    private function _divide_digit($dividend, $divisor)
    {
        $carry = 0;
        $result = array();

        for ($i = count($dividend) - 1; $i >= 0; --$i) {
            $temp = $this->baseFull * $carry + $dividend[$i];
            $result[$i] = (int) ($temp / $divisor);
            $carry = (int) ($temp - $divisor * $result[$i]);
        }

        return array($result, $carry);
    }

    /**
     * Performs modular exponentiation.
     *
     * Here's an example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger('10');
     *    $b = new Math\BigInteger('20');
     *    $c = new Math\BigInteger('30');
     *
     *    $c = $a->modPow($b, $c);
     *
     *    echo $c->toString(); // outputs 10
     * ?>
     * </code>
     *
     * @param Math\BigInteger $e
     * @param Math\BigInteger $n
     * @return Math\BigInteger
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
    public function modPow($e, $n)
    {
        $n = $this->bitmask !== false && $this->bitmask->compare($n) < 0 ? $this->bitmask : $n->abs();

        if ($e->compare(new BigInteger()) < 0) {
            $e = $e->abs();

            $temp = $this->modInverse($n);
            if ($temp === false) {
                return false;
            }

            return $this->_normalize($temp->modPow($e, $n));
        }

        if ( $this->mode == BigInteger::MODE_GMP ) {
            $temp = new BigInteger();
            $temp->value = gmp_powm($this->value, $e->value, $n->value);

            return $this->_normalize($temp);
        }

        if ($this->compare(new BigInteger()) < 0 || $this->compare($n) > 0) {
            list(, $temp) = $this->divide($n);
            return $temp->modPow($e, $n);
        }

        if ($this->isOpenSslEnabled()) {
            $components = array(
                'modulus' => $n->toBytes(true),
                'publicExponent' => $e->toBytes(true)
            );

            $components = array(
                'modulus' => pack('Ca*a*', 2, $this->_encodeASN1Length(strlen($components['modulus'])), $components['modulus']),
                'publicExponent' => pack('Ca*a*', 2, $this->_encodeASN1Length(strlen($components['publicExponent'])), $components['publicExponent'])
            );

            $RSAPublicKey = pack('Ca*a*a*',
                48, $this->_encodeASN1Length(strlen($components['modulus']) + strlen($components['publicExponent'])),
                $components['modulus'], $components['publicExponent']
            );

            $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
            $RSAPublicKey = chr(0) . $RSAPublicKey;
            $RSAPublicKey = chr(3) . $this->_encodeASN1Length(strlen($RSAPublicKey)) . $RSAPublicKey;

            $encapsulated = pack('Ca*a*',
                48, $this->_encodeASN1Length(strlen($rsaOID . $RSAPublicKey)), $rsaOID . $RSAPublicKey
            );

            $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
                             chunk_split(base64_encode($encapsulated)) .
                             '-----END PUBLIC KEY-----';

            $plaintext = str_pad($this->toBytes(), strlen($n->toBytes(true)) - 1, "\0", STR_PAD_LEFT);

            if (openssl_public_encrypt($plaintext, $result, $RSAPublicKey, OPENSSL_NO_PADDING)) {
                return new BigInteger($result, 256);
            }
        }

        if ( $this->mode == BigInteger::MODE_BCMATH ) {
                $temp = new BigInteger();
                $temp->value = bcpowmod($this->value, $e->value, $n->value, 0);

                return $this->_normalize($temp);
        }

        if ( empty($e->value) ) {
            $temp = new BigInteger();
            $temp->value = array(1);
            return $this->_normalize($temp);
        }

        if ( $e->value == array(1) ) {
            list(, $temp) = $this->divide($n);
            return $this->_normalize($temp);
        }

        if ( $e->value == array(2) ) {
            $temp = new BigInteger();
            $temp->value = $this->_square($this->value);
            list(, $temp) = $temp->divide($n);
            return $this->_normalize($temp);
        }

        return $this->_normalize($this->_slidingWindow($e, $n, BigInteger::BARRETT));

        // is the modulo odd?
        if ( $n->value[0] & 1 ) {
            return $this->_normalize($this->_slidingWindow($e, $n, BigInteger::MONTGOMERY));
        }
        // if it's not, it's even

        // find the lowest set bit (eg. the max pow of 2 that divides $n)
        for ($i = 0; $i < count($n->value); ++$i) {
            if ( $n->value[$i] ) {
                $temp = decbin($n->value[$i]);
                $j = strlen($temp) - strrpos($temp, '1') - 1;
                $j+= 26 * $i;
                break;
            }
        }
        // at this point, 2^$j * $n/(2^$j) == $n

        $mod1 = $n->copy();
        $mod1->_rshift($j);
        $mod2 = new BigInteger();
        $mod2->value = array(1);
        $mod2->_lshift($j);

        $part1 = ( $mod1->value != array(1) ) ? $this->_slidingWindow($e, $mod1, BigInteger::MONTGOMERY) : new BigInteger();
        $part2 = $this->_slidingWindow($e, $mod2, BigInteger::POWEROF2);

        $y1 = $mod2->modInverse($mod1);
        $y2 = $mod1->modInverse($mod2);

        $result = $part1->multiply($mod2);
        $result = $result->multiply($y1);

        $temp = $part2->multiply($mod1);
        $temp = $temp->multiply($y2);

        $result = $result->add($temp);
        list(, $result) = $result->divide($n);

        return $this->_normalize($result);
    }

    /**
     * Performs modular exponentiation.
     *
     * Alias for Math\BigInteger::modPow()
     *
     * @param Math\BigInteger $e
     * @param Math\BigInteger $n
     * @return Math\BigInteger
     * @access public
     */
    public function powMod($e, $n)
    {
        return $this->modPow($e, $n);
    }

    /**
     * Sliding Window k-ary Modular Exponentiation
     *
     * Based on {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=27 HAC 14.85} /
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=210 MPM 7.7}.  In a departure from those algorithims,
     * however, this function performs a modular reduction after every multiplication and squaring operation.
     * As such, this function has the same preconditions that the reductions being used do.
     *
     * @param Math\BigInteger $e
     * @param Math\BigInteger $n
     * @param Integer $mode
     * @return Math\BigInteger
     * @access private
     */
    private function _slidingWindow($e, $n, $mode)
    {
        static $window_ranges = array(7, 25, 81, 241, 673, 1793); // from BigInteger.java's oddModPow function
        //static $window_ranges = array(0, 7, 36, 140, 450, 1303, 3529); // from MPM 7.3.1

        $e_value = $e->value;
        $e_length = count($e_value) - 1;
        $e_bits = decbin($e_value[$e_length]);
        for ($i = $e_length - 1; $i >= 0; --$i) {
            $e_bits.= str_pad(decbin($e_value[$i]), $this->base, '0', STR_PAD_LEFT);
        }

        $e_length = strlen($e_bits);

        // calculate the appropriate window size.
        // $window_size == 3 if $window_ranges is between 25 and 81, for example.
        for ($i = 0, $window_size = 1; $e_length > $window_ranges[$i] && $i < count($window_ranges); ++$window_size, ++$i);

        $n_value = $n->value;

        // precompute $this^0 through $this^$window_size
        $powers = array();
        $powers[1] = $this->_prepareReduce($this->value, $n_value, $mode);
        $powers[2] = $this->_squareReduce($powers[1], $n_value, $mode);

        // we do every other number since substr($e_bits, $i, $j+1) (see below) is supposed to end
        // in a 1.  ie. it's supposed to be odd.
        $temp = 1 << ($window_size - 1);
        for ($i = 1; $i < $temp; ++$i) {
            $i2 = $i << 1;
            $powers[$i2 + 1] = $this->_multiplyReduce($powers[$i2 - 1], $powers[2], $n_value, $mode);
        }

        $result = array(1);
        $result = $this->_prepareReduce($result, $n_value, $mode);

        for ($i = 0; $i < $e_length; ) {
            if ( !$e_bits[$i] ) {
                $result = $this->_squareReduce($result, $n_value, $mode);
                ++$i;
            } else {
                for ($j = $window_size - 1; $j > 0; --$j) {
                    if ( !empty($e_bits[$i + $j]) ) {
                        break;
                    }
                }

                for ($k = 0; $k <= $j; ++$k) {// eg. the length of substr($e_bits, $i, $j+1)
                    $result = $this->_squareReduce($result, $n_value, $mode);
                }

                $result = $this->_multiplyReduce($result, $powers[bindec(substr($e_bits, $i, $j + 1))], $n_value, $mode);

                $i+=$j + 1;
            }
        }

        $temp = new BigInteger();
        $temp->value = $this->_reduce($result, $n_value, $mode);

        return $temp;
    }

    /**
     * Modular reduction
     *
     * For most $modes this will return the remainder.
     *
     * @see _slidingWindow()
     * @access private
     * @param Array $x
     * @param Array $n
     * @param Integer $mode
     * @return Array
     */
    private function _reduce($x, $n, $mode)
    {
        switch ($mode) {
            case BigInteger::MONTGOMERY:
                return $this->_montgomery($x, $n);
            case BigInteger::BARRETT:
                return $this->_barrett($x, $n);
            case BigInteger::POWEROF2:
                $lhs = new BigInteger();
                $lhs->value = $x;
                $rhs = new BigInteger();
                $rhs->value = $n;
                return $x->_mod2($n);
            case BigInteger::CLASSIC:
                $lhs = new BigInteger();
                $lhs->value = $x;
                $rhs = new BigInteger();
                $rhs->value = $n;
                list(, $temp) = $lhs->divide($rhs);
                return $temp->value;
            case BigInteger::NONE:
                return $x;
            default:
                // an invalid $mode was provided
        }
    }

    /**
     * Modular reduction preperation
     *
     * @see _slidingWindow()
     * @access private
     * @param Array $x
     * @param Array $n
     * @param Integer $mode
     * @return Array
     */
    private function _prepareReduce($x, $n, $mode)
    {
        if ($mode == BigInteger::MONTGOMERY) {
            return $this->_prepMontgomery($x, $n);
        }
        return $this->_reduce($x, $n, $mode);
    }

    /**
     * Modular multiply
     *
     * @see _slidingWindow()
     * @access private
     * @param Array $x
     * @param Array $y
     * @param Array $n
     * @param Integer $mode
     * @return Array
     */
    private function _multiplyReduce($x, $y, $n, $mode)
    {
        if ($mode == BigInteger::MONTGOMERY) {
            return $this->_montgomeryMultiply($x, $y, $n);
        }
        $temp = $this->_multiply($x, false, $y, false);
        return $this->_reduce($temp[BigInteger::VALUE], $n, $mode);
    }

    /**
     * Modular square
     *
     * @see _slidingWindow()
     * @access private
     * @param Array $x
     * @param Array $n
     * @param Integer $mode
     * @return Array
     */
    private function _squareReduce($x, $n, $mode)
    {
        if ($mode == BigInteger::MONTGOMERY) {
            return $this->_montgomeryMultiply($x, $x, $n);
        }
        return $this->_reduce($this->_square($x), $n, $mode);
    }

    /**
     * Modulos for Powers of Two
     *
     * Calculates $x%$n, where $n = 2**$e, for some $e.  Since this is basically the same as doing $x & ($n-1),
     * we'll just use this function as a wrapper for doing that.
     *
     * @see _slidingWindow()
     * @access private
     * @param Math\BigInteger
     * @return Math\BigInteger
     */
    private function _mod2($n)
    {
        $temp = new BigInteger();
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
     * Employs "folding", as described at
     * {@link http://www.cosic.esat.kuleuven.be/publications/thesis-149.pdf#page=66 thesis-149.pdf#page=66}.  To quote from
     * it, "the idea [behind folding] is to find a value x' such that x (mod m) = x' (mod m), with x' being smaller than x."
     *
     * Unfortunately, the "Barrett Reduction with Folding" algorithm described in thesis-149.pdf is not, as written, all that
     * usable on account of (1) its not using reasonable radix points as discussed in
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=162 MPM 6.2.2} and (2) the fact that, even with reasonable
     * radix points, it only works when there are an even number of digits in the denominator.  The reason for (2) is that
     * (x >> 1) + (x >> 1) != x / 2 + x / 2.  If x is even, they're the same, but if x is odd, they're not.  See the in-line
     * comments for details.
     *
     * @see _slidingWindow()
     * @access private
     * @param Array $n
     * @param Array $m
     * @return Array
     */
    private function _barrett($n, $m)
    {
        static $cache = array(
            BigInteger::VARIABLE => array(),
            BigInteger::DATA => array()
        );

        $m_length = count($m);

        // if ($this->_compare($n, $this->_square($m)) >= 0) {
        if (count($n) > 2 * $m_length) {
            $lhs = new BigInteger();
            $rhs = new BigInteger();
            $lhs->value = $n;
            $rhs->value = $m;
            list(, $temp) = $lhs->divide($rhs);
            return $temp->value;
        }

        // if (m.length >> 1) + 2 <= m.length then m is too small and n can't be reduced
        if ($m_length < 5) {
            return $this->_regularBarrett($n, $m);
        }

        // n = 2 * m.length

        if ( ($key = array_search($m, $cache[BigInteger::VARIABLE])) === false ) {
            $key = count($cache[BigInteger::VARIABLE]);
            $cache[BigInteger::VARIABLE][] = $m;

            $lhs = new BigInteger();
            $lhs_value = &$lhs->value;
            $lhs_value = $this->_array_repeat(0, $m_length + ($m_length >> 1));
            $lhs_value[] = 1;
            $rhs = new BigInteger();
            $rhs->value = $m;

            list($u, $m1) = $lhs->divide($rhs);
            $u = $u->value;
            $m1 = $m1->value;

            $cache[BigInteger::DATA][] = array(
                'u' => $u, // m.length >> 1 (technically (m.length >> 1) + 1)
                'm1'=> $m1 // m.length
            );
        } else {
            extract($cache[BigInteger::DATA][$key]);
        }

        $cutoff = $m_length + ($m_length >> 1);
        $lsd = array_slice($n, 0, $cutoff); // m.length + (m.length >> 1)
        $msd = array_slice($n, $cutoff);    // m.length >> 1
        $lsd = $this->_trim($lsd);
        $temp = $this->_multiply($msd, false, $m1, false);
        $n = $this->_add($lsd, false, $temp[BigInteger::VALUE], false); // m.length + (m.length >> 1) + 1

        if ($m_length & 1) {
            return $this->_regularBarrett($n[BigInteger::VALUE], $m);
        }

        // (m.length + (m.length >> 1) + 1) - (m.length - 1) == (m.length >> 1) + 2
        $temp = array_slice($n[BigInteger::VALUE], $m_length - 1);
        // if even: ((m.length >> 1) + 2) + (m.length >> 1) == m.length + 2
        // if odd:  ((m.length >> 1) + 2) + (m.length >> 1) == (m.length - 1) + 2 == m.length + 1
        $temp = $this->_multiply($temp, false, $u, false);
        // if even: (m.length + 2) - ((m.length >> 1) + 1) = m.length - (m.length >> 1) + 1
        // if odd:  (m.length + 1) - ((m.length >> 1) + 1) = m.length - (m.length >> 1)
        $temp = array_slice($temp[BigInteger::VALUE], ($m_length >> 1) + 1);
        // if even: (m.length - (m.length >> 1) + 1) + m.length = 2 * m.length - (m.length >> 1) + 1
        // if odd:  (m.length - (m.length >> 1)) + m.length     = 2 * m.length - (m.length >> 1)
        $temp = $this->_multiply($temp, false, $m, false);

        // at this point, if m had an odd number of digits, we'd be subtracting a 2 * m.length - (m.length >> 1) digit
        // number from a m.length + (m.length >> 1) + 1 digit number.  ie. there'd be an extra digit and the while loop
        // following this comment would loop a lot (hence our calling _regularBarrett() in that situation).

        $result = $this->_subtract($n[BigInteger::VALUE], false, $temp[BigInteger::VALUE], false);

        while ($this->_compare($result[BigInteger::VALUE], $result[BigInteger::SIGN], $m, false) >= 0) {
            $result = $this->_subtract($result[BigInteger::VALUE], $result[BigInteger::SIGN], $m, false);
        }

        return $result[BigInteger::VALUE];
    }

    /**
     * (Regular) Barrett Modular Reduction
     *
     * For numbers with more than four digits Math\BigInteger::_barrett() is faster.  The difference between that and this
     * is that this function does not fold the denominator into a smaller form.
     *
     * @see _slidingWindow()
     * @access private
     * @param Array $x
     * @param Array $n
     * @return Array
     */
    private function _regularBarrett($x, $n)
    {
        static $cache = array(
            BigInteger::VARIABLE => array(),
            BigInteger::DATA => array()
        );

        $n_length = count($n);

        if (count($x) > 2 * $n_length) {
            $lhs = new BigInteger();
            $rhs = new BigInteger();
            $lhs->value = $x;
            $rhs->value = $n;
            list(, $temp) = $lhs->divide($rhs);
            return $temp->value;
        }

        if ( ($key = array_search($n, $cache[BigInteger::VARIABLE])) === false ) {
            $key = count($cache[BigInteger::VARIABLE]);
            $cache[BigInteger::VARIABLE][] = $n;
            $lhs = new BigInteger();
            $lhs_value = &$lhs->value;
            $lhs_value = $this->_array_repeat(0, 2 * $n_length);
            $lhs_value[] = 1;
            $rhs = new BigInteger();
            $rhs->value = $n;
            list($temp, ) = $lhs->divide($rhs); // m.length
            $cache[BigInteger::DATA][] = $temp->value;
        }

        // 2 * m.length - (m.length - 1) = m.length + 1
        $temp = array_slice($x, $n_length - 1);
        // (m.length + 1) + m.length = 2 * m.length + 1
        $temp = $this->_multiply($temp, false, $cache[BigInteger::DATA][$key], false);
        // (2 * m.length + 1) - (m.length - 1) = m.length + 2
        $temp = array_slice($temp[BigInteger::VALUE], $n_length + 1);

        // m.length + 1
        $result = array_slice($x, 0, $n_length + 1);
        // m.length + 1
        $temp = $this->_multiplyLower($temp, false, $n, false, $n_length + 1);
        // $temp == array_slice($temp->_multiply($temp, false, $n, false)->value, 0, $n_length + 1)

        if ($this->_compare($result, false, $temp[BigInteger::VALUE], $temp[BigInteger::SIGN]) < 0) {
            $corrector_value = $this->_array_repeat(0, $n_length + 1);
            $corrector_value[] = 1;
            $result = $this->_add($result, false, $corrector_value, false);
            $result = $result[BigInteger::VALUE];
        }

        // at this point, we're subtracting a number with m.length + 1 digits from another number with m.length + 1 digits
        $result = $this->_subtract($result, false, $temp[BigInteger::VALUE], $temp[BigInteger::SIGN]);
        while ($this->_compare($result[BigInteger::VALUE], $result[BigInteger::SIGN], $n, false) > 0) {
            $result = $this->_subtract($result[BigInteger::VALUE], $result[BigInteger::SIGN], $n, false);
        }

        return $result[BigInteger::VALUE];
    }

    /**
     * Performs long multiplication up to $stop digits
     *
     * If you're going to be doing array_slice($product->value, 0, $stop), some cycles can be saved.
     *
     * @see _regularBarrett()
     * @param Array $x_value
     * @param Boolean $x_negative
     * @param Array $y_value
     * @param Boolean $y_negative
     * @param Integer $stop
     * @return Array
     * @access private
     */
    private function _multiplyLower($x_value, $x_negative, $y_value, $y_negative, $stop)
    {
        $x_length = count($x_value);
        $y_length = count($y_value);

        if ( !$x_length || !$y_length ) { // a 0 is being multiplied
            return array(
                BigInteger::VALUE => array(),
                BigInteger::SIGN => false
            );
        }

        if ( $x_length < $y_length ) {
            $temp = $x_value;
            $x_value = $y_value;
            $y_value = $temp;

            $x_length = count($x_value);
            $y_length = count($y_value);
        }

        $product_value = $this->_array_repeat(0, $x_length + $y_length);

        // the following for loop could be removed if the for loop following it
        // (the one with nested for loops) initially set $i to 0, but
        // doing so would also make the result in one set of unnecessary adds,
        // since on the outermost loops first pass, $product->value[$k] is going
        // to always be 0

        $carry = 0;

        for ($j = 0; $j < $x_length; ++$j) { // ie. $i = 0, $k = $i
            $temp = $x_value[$j] * $y_value[0] + $carry; // $product_value[$k] == 0
            $carry = (int) ($temp / $this->baseFull);
            $product_value[$j] = (int) ($temp - $this->baseFull * $carry);
        }

        if ($j < $stop) {
            $product_value[$j] = $carry;
        }

        // the above for loop is what the previous comment was talking about.  the
        // following for loop is the "one with nested for loops"

        for ($i = 1; $i < $y_length; ++$i) {
            $carry = 0;

            for ($j = 0, $k = $i; $j < $x_length && $k < $stop; ++$j, ++$k) {
                $temp = $product_value[$k] + $x_value[$j] * $y_value[$i] + $carry;
                $carry = (int) ($temp / $this->baseFull);
                $product_value[$k] = (int) ($temp - $this->baseFull * $carry);
            }

            if ($k < $stop) {
                $product_value[$k] = $carry;
            }
        }

        return array(
            BigInteger::VALUE => $this->_trim($product_value),
            BigInteger::SIGN => $x_negative != $y_negative
        );
    }

    /**
     * Montgomery Modular Reduction
     *
     * ($x->_prepMontgomery($n))->_montgomery($n) yields $x % $n.
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=170 MPM 6.3} provides insights on how this can be
     * improved upon (basically, by using the comba method).  gcd($n, 2) must be equal to one for this function
     * to work correctly.
     *
     * @see _prepMontgomery()
     * @see _slidingWindow()
     * @access private
     * @param Array $x
     * @param Array $n
     * @return Array
     */
    private function _montgomery($x, $n)
    {
        static $cache = array(
            BigInteger::VARIABLE => array(),
            BigInteger::DATA => array()
        );

        if ( ($key = array_search($n, $cache[BigInteger::VARIABLE])) === false ) {
            $key = count($cache[BigInteger::VARIABLE]);
            $cache[BigInteger::VARIABLE][] = $x;
            $cache[BigInteger::DATA][] = $this->_modInverse67108864($n);
        }

        $k = count($n);

        $result = array(BigInteger::VALUE => $x);

        for ($i = 0; $i < $k; ++$i) {
            $temp = $result[BigInteger::VALUE][$i] * $cache[BigInteger::DATA][$key];
            $temp = (int) ($temp - $this->baseFull * ((int) ($temp / $this->baseFull)));
            $temp = $this->_regularMultiply(array($temp), $n);
            $temp = array_merge($this->_array_repeat(0, $i), $temp);
            $result = $this->_add($result[BigInteger::VALUE], false, $temp, false);
        }

        $result[BigInteger::VALUE] = array_slice($result[BigInteger::VALUE], $k);

        if ($this->_compare($result, false, $n, false) >= 0) {
            $result = $this->_subtract($result[BigInteger::VALUE], false, $n, false);
        }

        return $result[BigInteger::VALUE];
    }

    /**
     * Montgomery Multiply
     *
     * Interleaves the montgomery reduction and long multiplication algorithms together as described in 
     * {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=13 HAC 14.36}
     *
     * @see _prepMontgomery()
     * @see _montgomery()
     * @access private
     * @param Array $x
     * @param Array $y
     * @param Array $m
     * @return Array
     */
    private function _montgomeryMultiply($x, $y, $m)
    {
        $temp = $this->_multiply($x, false, $y, false);
        return $this->_montgomery($temp[BigInteger::VALUE], $m);

        static $cache = array(
            BigInteger::VARIABLE => array(),
            BigInteger::DATA => array()
        );

        if ( ($key = array_search($m, $cache[BigInteger::VARIABLE])) === false ) {
            $key = count($cache[BigInteger::VARIABLE]);
            $cache[BigInteger::VARIABLE][] = $m;
            $cache[BigInteger::DATA][] = $this->_modInverse67108864($m);
        }

        $n = max(count($x), count($y), count($m));
        $x = array_pad($x, $n, 0);
        $y = array_pad($y, $n, 0);
        $m = array_pad($m, $n, 0);
        $a = array(BigInteger::VALUE => $this->_array_repeat(0, $n + 1));
        for ($i = 0; $i < $n; ++$i) {
            $temp = $a[BigInteger::VALUE][0] + $x[$i] * $y[0];
            $temp = (int) ($temp - $this->baseFull * ((int) ($temp / $this->baseFull)));
            $temp = $temp * $cache[BigInteger::DATA][$key];
            $temp = (int) ($temp - $this->baseFull * ((int) ($temp / $this->baseFull)));
            $temp = $this->_add($this->_regularMultiply(array($x[$i]), $y), false, $this->_regularMultiply(array($temp), $m), false);
            $a = $this->_add($a[BigInteger::VALUE], false, $temp[BigInteger::VALUE], false);
            $a[BigInteger::VALUE] = array_slice($a[BigInteger::VALUE], 1);
        }
        if ($this->_compare($a[BigInteger::VALUE], false, $m, false) >= 0) {
            $a = $this->_subtract($a[BigInteger::VALUE], false, $m, false);
        }
        return $a[BigInteger::VALUE];
    }

    /**
     * Prepare a number for use in Montgomery Modular Reductions
     *
     * @see _montgomery()
     * @see _slidingWindow()
     * @access private
     * @param Array $x
     * @param Array $n
     * @return Array
     */
    private function _prepMontgomery($x, $n)
    {
        $lhs = new BigInteger();
        $lhs->value = array_merge($this->_array_repeat(0, count($n)), $x);
        $rhs = new BigInteger();
        $rhs->value = $n;

        list(, $temp) = $lhs->divide($rhs);
        return $temp->value;
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
     * As for why we do all the bitmasking...  strange things can happen when converting from floats to ints. For
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
     * @param Array $x
     * @return Integer
     */
    private function _modInverse67108864($x) // 2**26 == 67,108,864
    {
        $x = -$x[0];
        $result = $x & 0x3; // x**-1 mod 2**2
        $result = ($result * (2 - $x * $result)) & 0xF; // x**-1 mod 2**4
        $result = ($result * (2 - ($x & 0xFF) * $result))  & 0xFF; // x**-1 mod 2**8
        $result = ($result * ((2 - ($x & 0xFFFF) * $result) & 0xFFFF)) & 0xFFFF; // x**-1 mod 2**16
        $result = fmod($result * (2 - fmod($x * $result, $this->baseFull)), $this->baseFull); // x**-1 mod 2**26
        return $result & $this->maxDigit;
    }

    /**
     * Calculates modular inverses.
     *
     * Say you have (30 mod 17 * x mod 17) mod 17 == 1.  x can be found using modular inverses.
     *
     * Here's an example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger(30);
     *    $b = new Math\BigInteger(17);
     *
     *    $c = $a->modInverse($b);
     *    echo $c->toString(); // outputs 4
     *
     *    echo "\r\n";
     *
     *    $d = $a->multiply($c);
     *    list(, $d) = $d->divide($b);
     *    echo $d; // outputs 1 (as per the definition of modular inverse)
     * ?>
     * </code>
     *
     * @param Math\BigInteger $n
     * @return mixed false, if no modular inverse exists, Math\BigInteger, otherwise.
     * @access public
     * @internal See {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=21 HAC 14.64} for more information.
     */
    public function modInverse($n)
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                $temp = new BigInteger();
                $temp->value = gmp_invert($this->value, $n->value);

                return ( $temp->value === false ) ? false : $this->_normalize($temp);
        }

        static $zero, $one;
        if (!isset($zero)) {
            $zero = new BigInteger();
            $one = new BigInteger(1);
        }

        // $x mod -$n == $x mod $n.
        $n = $n->abs();

        if ($this->compare($zero) < 0) {
            $temp = $this->abs();
            $temp = $temp->modInverse($n);
            return $this->_normalize($n->subtract($temp));
        }

        extract($this->extendedGCD($n));

        if (!$gcd->equals($one)) {
            return false;
        }

        $x = $x->compare($zero) < 0 ? $x->add($n) : $x;

        return $this->compare($zero) < 0 ? $this->_normalize($n->subtract($x)) : $this->_normalize($x);
    }

    /**
     * Calculates the greatest common divisor and Bezout's identity.
     *
     * Say you have 693 and 609.  The GCD is 21.  Bezout's identity states that there exist integers x and y such that
     * 693*x + 609*y == 21.  In point of fact, there are actually an infinite number of x and y combinations and which
     * combination is returned is dependant upon which mode is in use.  See
     * {@link http://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity Bezout's identity - Wikipedia} for more information.
     *
     * Here's an example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger(693);
     *    $b = new Math\BigInteger(609);
     *
     *    extract($a->extendedGCD($b));
     *
     *    echo $gcd->toString() . "\r\n"; // outputs 21
     *    echo $a->toString() * $x->toString() + $b->toString() * $y->toString(); // outputs 21
     * ?>
     * </code>
     *
     * @param Math\BigInteger $n
     * @return Math\BigInteger
     * @access public
     * @internal Calculates the GCD using the binary xGCD algorithim described in
     *    {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=19 HAC 14.61}.  As the text above 14.61 notes,
     *    the more traditional algorithim requires "relatively costly multiple-precision divisions".
     */
    public function extendedGCD($n)
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                extract(gmp_gcdext($this->value, $n->value));

                return array(
                    'gcd' => $this->_normalize(new BigInteger($g)),
                    'x'   => $this->_normalize(new BigInteger($s)),
                    'y'   => $this->_normalize(new BigInteger($t))
                );
            case BigInteger::MODE_BCMATH:
                // it might be faster to use the binary xGCD algorithim here, as well, but (1) that algorithim works
                // best when the base is a power of 2 and (2) i don't think it'd make much difference, anyway.  as is,
                // the basic extended euclidean algorithim is what we're using.

                $u = $this->value;
                $v = $n->value;

                $a = '1';
                $b = '0';
                $c = '0';
                $d = '1';

                while (bccomp($v, '0', 0) != 0) {
                    $q = bcdiv($u, $v, 0);

                    $temp = $u;
                    $u = $v;
                    $v = bcsub($temp, bcmul($v, $q, 0), 0);

                    $temp = $a;
                    $a = $c;
                    $c = bcsub($temp, bcmul($a, $q, 0), 0);

                    $temp = $b;
                    $b = $d;
                    $d = bcsub($temp, bcmul($b, $q, 0), 0);
                }

                return array(
                    'gcd' => $this->_normalize(new BigInteger($u)),
                    'x'   => $this->_normalize(new BigInteger($a)),
                    'y'   => $this->_normalize(new BigInteger($b))
                );
        }

        $y = $n->copy();
        $x = $this->copy();
        $g = new BigInteger();
        $g->value = array(1);

        while ( !(($x->value[0] & 1)|| ($y->value[0] & 1)) ) {
            $x->_rshift(1);
            $y->_rshift(1);
            $g->_lshift(1);
        }

        $u = $x->copy();
        $v = $y->copy();

        $a = new BigInteger();
        $b = new BigInteger();
        $c = new BigInteger();
        $d = new BigInteger();

        $a->value = $d->value = $g->value = array(1);
        $b->value = $c->value = array();

        while ( !empty($u->value) ) {
            while ( !($u->value[0] & 1) ) {
                $u->_rshift(1);
                if ( (!empty($a->value) && ($a->value[0] & 1)) || (!empty($b->value) && ($b->value[0] & 1)) ) {
                    $a = $a->add($y);
                    $b = $b->subtract($x);
                }
                $a->_rshift(1);
                $b->_rshift(1);
            }

            while ( !($v->value[0] & 1) ) {
                $v->_rshift(1);
                if ( (!empty($d->value) && ($d->value[0] & 1)) || (!empty($c->value) && ($c->value[0] & 1)) ) {
                    $c = $c->add($y);
                    $d = $d->subtract($x);
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
        }

        return array(
            'gcd' => $this->_normalize($g->multiply($v)),
            'x'   => $this->_normalize($c),
            'y'   => $this->_normalize($d)
        );
    }

    /**
     * Calculates the greatest common divisor
     *
     * Say you have 693 and 609.  The GCD is 21.
     *
     * Here's an example:
     * <code>
     * <?php
     *    include('Math/BigInteger.php');
     *
     *    $a = new Math\BigInteger(693);
     *    $b = new Math\BigInteger(609);
     *
     *    $gcd = a->extendedGCD($b);
     *
     *    echo $gcd->toString() . "\r\n"; // outputs 21
     * ?>
     * </code>
     *
     * @param Math\BigInteger $n
     * @return Math\BigInteger
     * @access public
     */
    public function gcd($n)
    {
        extract($this->extendedGCD($n));
        return $gcd;
    }

    /**
     * Absolute value.
     *
     * @return Math\BigInteger
     * @access public
     */
    public function abs()
    {
        $temp = new BigInteger();

        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                $temp->value = gmp_abs($this->value);
                break;
            case BigInteger::MODE_BCMATH:
                $temp->value = (bccomp($this->value, '0', 0) < 0) ? substr($this->value, 1) : $this->value;
                break;
            default:
                $temp->value = $this->value;
        }

        return $temp;
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
     * @param Math\BigInteger $y
     * @return Integer < 0 if $this is less than $y; > 0 if $this is greater than $y, and 0 if they are equal.
     * @access public
     * @see equals()
     * @internal Could return $this->subtract($x), but that's not as fast as what we do do.
     */
    public function compare($y)
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                return gmp_cmp($this->value, $y->value);
            case BigInteger::MODE_BCMATH:
                return bccomp($this->value, $y->value, 0);
        }

        return $this->_compare($this->value, $this->is_negative, $y->value, $y->is_negative);
    }

    /**
     * Compares two numbers.
     *
     * @param Array $x_value
     * @param Boolean $x_negative
     * @param Array $y_value
     * @param Boolean $y_negative
     * @return Integer
     * @see compare()
     * @access private
     */
    private function _compare($x_value, $x_negative, $y_value, $y_negative)
    {
        if ( $x_negative != $y_negative ) {
            return ( !$x_negative && $y_negative ) ? 1 : -1;
        }

        $result = $x_negative ? -1 : 1;

        if ( count($x_value) != count($y_value) ) {
            return ( count($x_value) > count($y_value) ) ? $result : -$result;
        }
        $size = max(count($x_value), count($y_value));

        $x_value = array_pad($x_value, $size, 0);
        $y_value = array_pad($y_value, $size, 0);

        for ($i = count($x_value) - 1; $i >= 0; --$i) {
            if ($x_value[$i] != $y_value[$i]) {
                return ( $x_value[$i] > $y_value[$i] ) ? $result : -$result;
            }
        }

        return 0;
    }

    /**
     * Tests the equality of two numbers.
     *
     * If you need to see if one number is greater than or less than another number, use Math\BigInteger::compare()
     *
     * @param Math\BigInteger $x
     * @return Boolean
     * @access public
     * @see compare()
     */
    public function equals($x)
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                return gmp_cmp($this->value, $x->value) == 0;
            default:
                return $this->value === $x->value && $this->is_negative == $x->is_negative;
        }
    }

    /**
     * Set Precision
     *
     * Some bitwise operations give different results depending on the precision being used.  Examples include left
     * shift, not, and rotates.
     *
     * @param Integer $bits
     * @access public
     */
    public function setPrecision($bits)
    {
        $this->precision = $bits;
        if ( $this->mode != BigInteger::MODE_BCMATH ) {
            $this->bitmask = new BigInteger(chr((1 << ($bits & 0x7)) - 1) . str_repeat(chr(0xFF), $bits >> 3), 256);
        } else {
            $this->bitmask = new BigInteger(bcpow('2', $bits, 0));
        }

        $temp = $this->_normalize($this);
        $this->value = $temp->value;
    }

    /**
     * Logical And
     *
     * @param Math\BigInteger $x
     * @access public
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     * @return Math\BigInteger
     */
    public function bitwise_and($x)
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                $temp = new BigInteger();
                $temp->value = gmp_and($this->value, $x->value);

                return $this->_normalize($temp);
            case BigInteger::MODE_BCMATH:
                $left = $this->toBytes();
                $right = $x->toBytes();

                $length = max(strlen($left), strlen($right));

                $left = str_pad($left, $length, chr(0), STR_PAD_LEFT);
                $right = str_pad($right, $length, chr(0), STR_PAD_LEFT);

                return $this->_normalize(new BigInteger($left & $right, 256));
        }

        $result = $this->copy();

        $length = min(count($x->value), count($this->value));

        $result->value = array_slice($result->value, 0, $length);

        for ($i = 0; $i < $length; ++$i) {
            $result->value[$i]&= $x->value[$i];
        }

        return $this->_normalize($result);
    }

    /**
     * Logical Or
     *
     * @param Math\BigInteger $x
     * @access public
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     * @return Math\BigInteger
     */
    public function bitwise_or($x)
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                $temp = new BigInteger();
                $temp->value = gmp_or($this->value, $x->value);

                return $this->_normalize($temp);
            case BigInteger::MODE_BCMATH:
                $left = $this->toBytes();
                $right = $x->toBytes();

                $length = max(strlen($left), strlen($right));

                $left = str_pad($left, $length, chr(0), STR_PAD_LEFT);
                $right = str_pad($right, $length, chr(0), STR_PAD_LEFT);

                return $this->_normalize(new BigInteger($left | $right, 256));
        }

        $length = max(count($this->value), count($x->value));
        $result = $this->copy();
        $result->value = array_pad($result->value, $length, 0);
        $x->value = array_pad($x->value, $length, 0);

        for ($i = 0; $i < $length; ++$i) {
            $result->value[$i]|= $x->value[$i];
        }

        return $this->_normalize($result);
    }

    /**
     * Logical Exclusive-Or
     *
     * @param Math\BigInteger $x
     * @access public
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     * @return Math\BigInteger
     */
    public function bitwise_xor($x)
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                $temp = new BigInteger();
                $temp->value = gmp_xor($this->value, $x->value);

                return $this->_normalize($temp);
            case BigInteger::MODE_BCMATH:
                $left = $this->toBytes();
                $right = $x->toBytes();

                $length = max(strlen($left), strlen($right));

                $left = str_pad($left, $length, chr(0), STR_PAD_LEFT);
                $right = str_pad($right, $length, chr(0), STR_PAD_LEFT);

                return $this->_normalize(new BigInteger($left ^ $right, 256));
        }

        $length = max(count($this->value), count($x->value));
        $result = $this->copy();
        $result->value = array_pad($result->value, $length, 0);
        $x->value = array_pad($x->value, $length, 0);

        for ($i = 0; $i < $length; ++$i) {
            $result->value[$i]^= $x->value[$i];
        }

        return $this->_normalize($result);
    }

    /**
     * Logical Not
     *
     * @access public
     * @internal Implemented per a request by Lluis Pamies i Juarez <lluis _a_ pamies.cat>
     * @return Math\BigInteger
     */
    public function bitwise_not()
    {
        // calculuate "not" without regard to $this->precision
        // (will always result in a smaller number.  ie. ~1 isn't 1111 1110 - it's 0)
        $temp = $this->toBytes();
        $pre_msb = decbin(ord($temp[0]));
        $temp = ~$temp;
        $msb = decbin(ord($temp[0]));
        if (strlen($msb) == 8) {
            $msb = substr($msb, strpos($msb, '0'));
        }
        $temp[0] = chr(bindec($msb));

        // see if we need to add extra leading 1's
        $current_bits = strlen($pre_msb) + 8 * strlen($temp) - 8;
        $new_bits = $this->precision - $current_bits;
        if ($new_bits <= 0) {
            return $this->_normalize(new BigInteger($temp, 256));
        }

        // generate as many leading 1's as we need to.
        $leading_ones = chr((1 << ($new_bits & 0x7)) - 1) . str_repeat(chr(0xFF), $new_bits >> 3);
        $this->_base256_lshift($leading_ones, $current_bits);

        $temp = str_pad($temp, ceil($this->bits / 8), chr(0), STR_PAD_LEFT);

        return $this->_normalize(new BigInteger($leading_ones | $temp, 256));
    }

    /**
     * Logical Right Shift
     *
     * Shifts BigInteger's by $shift bits, effectively dividing by 2**$shift.
     *
     * @param Integer $shift
     * @return Math\BigInteger
     * @access public
     * @internal The only version that yields any speed increases is the internal version.
     */
    public function bitwise_rightShift($shift)
    {
        $temp = new BigInteger();

        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                static $two;

                if (!isset($two)) {
                    $two = gmp_init('2');
                }

                $temp->value = gmp_div_q($this->value, gmp_pow($two, $shift));

                break;
            case BigInteger::MODE_BCMATH:
                $temp->value = bcdiv($this->value, bcpow('2', $shift, 0), 0);

                break;
            default: // could just replace _lshift with this, but then all _lshift() calls would need to be rewritten
                     // and I don't want to do that...
                $temp->value = $this->value;
                $temp->_rshift($shift);
        }

        return $this->_normalize($temp);
    }

    /**
     * Logical Left Shift
     *
     * Shifts BigInteger's by $shift bits, effectively multiplying by 2**$shift.
     *
     * @param Integer $shift
     * @return Math\BigInteger
     * @access public
     * @internal The only version that yields any speed increases is the internal version.
     */
    public function bitwise_leftShift($shift)
    {
        $temp = new BigInteger();

        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                static $two;

                if (!isset($two)) {
                    $two = gmp_init('2');
                }

                $temp->value = gmp_mul($this->value, gmp_pow($two, $shift));

                break;
            case BigInteger::MODE_BCMATH:
                $temp->value = bcmul($this->value, bcpow('2', $shift, 0), 0);

                break;
            default: // could just replace _rshift with this, but then all _lshift() calls would need to be rewritten
                     // and I don't want to do that...
                $temp->value = $this->value;
                $temp->_lshift($shift);
        }

        return $this->_normalize($temp);
    }

    /**
     * Logical Left Rotate
     *
     * Instead of the top x bits being dropped they're appended to the shifted bit string.
     *
     * @param Integer $shift
     * @return Math\BigInteger
     * @access public
     */
    public function bitwise_leftRotate($shift)
    {
        $bits = $this->toBytes();

        if ($this->precision > 0) {
            $precision = $this->precision;
            if ( $this->mode == BigInteger::MODE_BCMATH ) {
                $mask = $this->bitmask->subtract(new BigInteger(1));
                $mask = $mask->toBytes();
            } else {
                $mask = $this->bitmask->toBytes();
            }
        } else {
            $temp = ord($bits[0]);
            for ($i = 0; $temp >> $i; ++$i);
            $precision = 8 * strlen($bits) - 8 + $i;
            $mask = chr((1 << ($precision & 0x7)) - 1) . str_repeat(chr(0xFF), $precision >> 3);
        }

        if ($shift < 0) {
            $shift+= $precision;
        }
        $shift%= $precision;

        if (!$shift) {
            return $this->copy();
        }

        $left = $this->bitwise_leftShift($shift);
        $left = $left->bitwise_and(new BigInteger($mask, 256));
        $right = $this->bitwise_rightShift($precision - $shift);
        $result = $this->mode != BigInteger::MODE_BCMATH ? $left->bitwise_or($right) : $left->add($right);
        return $this->_normalize($result);
    }

    /**
     * Logical Right Rotate
     *
     * Instead of the bottom x bits being dropped they're prepended to the shifted bit string.
     *
     * @param Integer $shift
     * @return Math\BigInteger
     * @access public
     */
    public function bitwise_rightRotate($shift)
    {
        return $this->bitwise_leftRotate(-$shift);
    }

    /**
     * Set random number generator function
     *
     * This function is deprecated.
     *
     * @param String $generator
     * @access public
     */
    public function setRandomGenerator($generator)
    {
    }

    /**
     * Generates a random BigInteger
     *
     * Byte length is equal to $length. Uses crypt_random if it's loaded and mt_rand if it's not.
     *
     * @param Integer $length
     * @return Math\BigInteger
     * @access private
     */
    private function _random_number_helper($size)
    {
        $crypt_random = class_exists('phpseclib\Crypt\Random') && method_exists('phpseclib\Crypt\Random', 'crypt_random_string');
        if ($crypt_random) {
            $random = Random::crypt_random_string($size);
        } else {
            $random = '';

            if ($size & 1) {
                $random.= chr(mt_rand(0, 255));
            }

            $blocks = $size >> 1;
            for ($i = 0; $i < $blocks; ++$i) {
                // mt_rand(-2147483648, 0x7FFFFFFF) always produces -2147483648 on some systems
                $random.= pack('n', mt_rand(0, 0xFFFF));
            }
        }

        return new BigInteger($random, 256);
    }

    /**
     * Generate a random number
     *
     * @param optional Integer $min
     * @param optional Integer $max
     * @return Math\BigInteger
     * @access public
     */
    public function random($min = false, $max = false)
    {
        if ($min === false) {
            $min = new BigInteger(0);
        }

        if ($max === false) {
            $max = new BigInteger(0x7FFFFFFF);
        }

        $compare = $max->compare($min);

        if (!$compare) {
            return $this->_normalize($min);
        } else if ($compare < 0) {
            // if $min is bigger then $max, swap $min and $max
            $temp = $max;
            $max = $min;
            $min = $temp;
        }

        static $one;
        if (!isset($one)) {
            $one = new BigInteger(1);
        }

        $max = $max->subtract($min->subtract($one));
        $size = strlen(ltrim($max->toBytes(), chr(0)));

        /*
            doing $random % $max doesn't work because some numbers will be more likely to occur than others.
            eg. if $max is 140 and $random's max is 255 then that'd mean both $random = 5 and $random = 145
            would produce 5 whereas the only value of random that could produce 139 would be 139. ie.
            not all numbers would be equally likely. some would be more likely than others.

            creating a whole new random number until you find one that is within the range doesn't work
            because, for sufficiently small ranges, the likelihood that you'd get a number within that range
            would be pretty small. eg. with $random's max being 255 and if your $max being 1 the probability
            would be pretty high that $random would be greater than $max.

            phpseclib works around this using the technique described here:

            http://crypto.stackexchange.com/questions/5708/creating-a-small-number-from-a-cryptographically-secure-random-string
        */
        $random_max = new BigInteger(chr(1) . str_repeat("\0", $size), 256);
        $random = $this->_random_number_helper($size);

        list($max_multiple) = $random_max->divide($max);
        $max_multiple = $max_multiple->multiply($max);

        while ($random->compare($max_multiple) >= 0) {
            $random = $random->subtract($max_multiple);
            $random_max = $random_max->subtract($max_multiple);
            $random = $random->bitwise_leftShift(8);
            $random = $random->add($this->_random_number_helper(1));
            $random_max = $random_max->bitwise_leftShift(8);
            list($max_multiple) = $random_max->divide($max);
            $max_multiple = $max_multiple->multiply($max);
        }
        list(, $random) = $random->divide($max);

        return $this->_normalize($random->add($min));
    }

    /**
     * Generate a random prime number.
     *
     * If there's not a prime within the given range, false will be returned.  If more than $timeout seconds have elapsed,
     * give up and return false.
     *
     * @param optional Integer $min
     * @param optional Integer $max
     * @param optional Integer $timeout
     * @return Math\BigInteger
     * @access public
     * @internal See {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap4.pdf#page=15 HAC 4.44}.
     */
    public function randomPrime($min = false, $max = false, $timeout = false)
    {
        if ($min === false) {
            $min = new BigInteger(0);
        }

        if ($max === false) {
            $max = new BigInteger(0x7FFFFFFF);
        }

        $compare = $max->compare($min);

        if (!$compare) {
            return $min->isPrime() ? $min : false;
        } else if ($compare < 0) {
            // if $min is bigger then $max, swap $min and $max
            $temp = $max;
            $max = $min;
            $min = $temp;
        }

        static $one, $two;
        if (!isset($one)) {
            $one = new BigInteger(1);
            $two = new BigInteger(2);
        }

        $start = time();

        $x = $this->random($min, $max);

        // gmp_nextprime() requires PHP 5 >= 5.2.0 per <http://php.net/gmp-nextprime>.
        if ( $this->mode == BigInteger::MODE_GMP && function_exists('gmp_nextprime') ) {
            $p = new BigInteger();
            $p->value = gmp_nextprime($x->value);

            if ($p->compare($max) <= 0) {
                return $p;
            }

            if (!$min->equals($x)) {
                $x = $x->subtract($one);
            }

            return $x->randomPrime($min, $x);
        }

        if ($x->equals($two)) {
            return $x;
        }

        $x->_make_odd();
        if ($x->compare($max) > 0) {
            // if $x > $max then $max is even and if $min == $max then no prime number exists between the specified range
            if ($min->equals($max)) {
                return false;
            }
            $x = $min->copy();
            $x->_make_odd();
        }

        $initial_x = $x->copy();

        while (true) {
            if ($timeout !== false && time() - $start > $timeout) {
                return false;
            }

            if ($x->isPrime()) {
                return $x;
            }

            $x = $x->add($two);

            if ($x->compare($max) > 0) {
                $x = $min->copy();
                if ($x->equals($two)) {
                    return $x;
                }
                $x->_make_odd();
            }

            if ($x->equals($initial_x)) {
                return false;
            }
        }
    }

    /**
     * Make the current number odd
     *
     * If the current number is odd it'll be unchanged.  If it's even, one will be added to it.
     *
     * @see randomPrime()
     * @access private
     */
    private function _make_odd()
    {
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                gmp_setbit($this->value, 0);
                break;
            case BigInteger::MODE_BCMATH:
                if ($this->value[strlen($this->value) - 1] % 2 == 0) {
                    $this->value = bcadd($this->value, '1');
                }
                break;
            default:
                $this->value[0] |= 1;
        }
    }

    /**
     * Checks a numer to see if it's prime
     *
     * Assuming the $t parameter is not set, this function has an error rate of 2**-80.  The main motivation for the
     * $t parameter is distributability.  Math\BigInteger::randomPrime() can be distributed accross multiple pageloads
     * on a website instead of just one.
     *
     * @param optional Integer $t
     * @return Boolean
     * @access public
     * @internal Uses the
     *     {@link http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test Miller-Rabin primality test}.  See 
     *     {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap4.pdf#page=8 HAC 4.24}.
     */
    public function isPrime($t = false)
    {
        $length = strlen($this->toBytes());

        if (!$t) {
            // see HAC 4.49 "Note (controlling the error probability)"
            // @codingStandardsIgnoreStart
                 if ($length >= 163) { $t =  2; } // floor(1300 / 8)
            else if ($length >= 106) { $t =  3; } // floor( 850 / 8)
            else if ($length >= 81 ) { $t =  4; } // floor( 650 / 8)
            else if ($length >= 68 ) { $t =  5; } // floor( 550 / 8)
            else if ($length >= 56 ) { $t =  6; } // floor( 450 / 8)
            else if ($length >= 50 ) { $t =  7; } // floor( 400 / 8)
            else if ($length >= 43 ) { $t =  8; } // floor( 350 / 8)
            else if ($length >= 37 ) { $t =  9; } // floor( 300 / 8)
            else if ($length >= 31 ) { $t = 12; } // floor( 250 / 8)
            else if ($length >= 25 ) { $t = 15; } // floor( 200 / 8)
            else if ($length >= 18 ) { $t = 18; } // floor( 150 / 8)
            else                     { $t = 27; }
            // @codingStandardsIgnoreEnd
        }

        // ie. gmp_testbit($this, 0)
        // ie. isEven() or !isOdd()
        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                return gmp_prob_prime($this->value, $t) != 0;
            case BigInteger::MODE_BCMATH:
                if ($this->value === '2') {
                    return true;
                }
                if ($this->value[strlen($this->value) - 1] % 2 == 0) {
                    return false;
                }
                break;
            default:
                if ($this->value == array(2)) {
                    return true;
                }
                if (~$this->value[0] & 1) {
                    return false;
                }
        }

        static $primes, $zero, $one, $two;

        if (!isset($primes)) {
            $primes = array(
                3,    5,    7,    11,   13,   17,   19,   23,   29,   31,   37,   41,   43,   47,   53,   59,   
                61,   67,   71,   73,   79,   83,   89,   97,   101,  103,  107,  109,  113,  127,  131,  137,  
                139,  149,  151,  157,  163,  167,  173,  179,  181,  191,  193,  197,  199,  211,  223,  227,  
                229,  233,  239,  241,  251,  257,  263,  269,  271,  277,  281,  283,  293,  307,  311,  313,  
                317,  331,  337,  347,  349,  353,  359,  367,  373,  379,  383,  389,  397,  401,  409,  419,  
                421,  431,  433,  439,  443,  449,  457,  461,  463,  467,  479,  487,  491,  499,  503,  509,  
                521,  523,  541,  547,  557,  563,  569,  571,  577,  587,  593,  599,  601,  607,  613,  617,  
                619,  631,  641,  643,  647,  653,  659,  661,  673,  677,  683,  691,  701,  709,  719,  727,  
                733,  739,  743,  751,  757,  761,  769,  773,  787,  797,  809,  811,  821,  823,  827,  829,  
                839,  853,  857,  859,  863,  877,  881,  883,  887,  907,  911,  919,  929,  937,  941,  947,  
                953,  967,  971,  977,  983,  991,  997
            );

            if ( $this->mode != BigInteger::MODE_INTERNAL ) {
                for ($i = 0; $i < count($primes); ++$i) {
                    $primes[$i] = new BigInteger($primes[$i]);
                }
            }

            $zero = new BigInteger();
            $one = new BigInteger(1);
            $two = new BigInteger(2);
        }

        if ($this->equals($one)) {
            return false;
        }

        // see HAC 4.4.1 "Random search for probable primes"
        if ( $this->mode != BigInteger::MODE_INTERNAL ) {
            foreach ($primes as $prime) {
                list(, $r) = $this->divide($prime);
                if ($r->equals($zero)) {
                    return $this->equals($prime);
                }
            }
        } else {
            $value = $this->value;
            foreach ($primes as $prime) {
                list(, $r) = $this->_divide_digit($value, $prime);
                if (!$r) {
                    return count($value) == 1 && $value[0] == $prime;
                }
            }
        }

        $n   = $this->copy();
        $n_1 = $n->subtract($one);
        $n_2 = $n->subtract($two);

        $r = $n_1->copy();
        $r_value = $r->value;
        // ie. $s = gmp_scan1($n, 0) and $r = gmp_div_q($n, gmp_pow(gmp_init('2'), $s));
        if ( $this->mode == BigInteger::MODE_BCMATH ) {
            $s = 0;
            // if $n was 1, $r would be 0 and this would be an infinite loop, hence our $this->equals($one) check earlier
            while ($r->value[strlen($r->value) - 1] % 2 == 0) {
                $r->value = bcdiv($r->value, '2', 0);
                ++$s;
            }
        } else {
            for ($i = 0, $r_length = count($r_value); $i < $r_length; ++$i) {
                $temp = ~$r_value[$i] & 0xFFFFFF;
                for ($j = 1; ($temp >> $j) & 1; ++$j);
                if ($j != 25) {
                    break;
                }
            }
            $s = 26 * $i + $j - 1;
            $r->_rshift($s);
        }

        for ($i = 0; $i < $t; ++$i) {
            $a = $this->random($two, $n_2);
            $y = $a->modPow($r, $n);

            if (!$y->equals($one) && !$y->equals($n_1)) {
                for ($j = 1; $j < $s && !$y->equals($n_1); ++$j) {
                    $y = $y->modPow($two, $n);
                    if ($y->equals($one)) {
                        return false;
                    }
                }

                if (!$y->equals($n_1)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Logical Left Shift
     *
     * Shifts BigInteger's by $shift bits.
     *
     * @param Integer $shift
     * @access private
     */
    private function _lshift($shift)
    {
        if ( $shift == 0 ) {
            return;
        }

        $num_digits = (int) ($shift / $this->base);
        $shift %= $this->base;
        $shift = 1 << $shift;

        $carry = 0;

        for ($i = 0; $i < count($this->value); ++$i) {
            $temp = $this->value[$i] * $shift + $carry;
            $carry = (int) ($temp / $this->baseFull);
            $this->value[$i] = (int) ($temp - $carry * $this->baseFull);
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
    private function _rshift($shift)
    {
        if ($shift == 0) {
            return;
        }

        $num_digits = (int) ($shift / $this->base);
        $shift %= $this->base;
        $carry_shift = $this->base - $shift;
        $carry_mask = (1 << $shift) - 1;

        if ( $num_digits ) {
            $this->value = array_slice($this->value, $num_digits);
        }

        $carry = 0;

        for ($i = count($this->value) - 1; $i >= 0; --$i) {
            $temp = $this->value[$i] >> $shift | $carry;
            $carry = ($this->value[$i] & $carry_mask) << $carry_shift;
            $this->value[$i] = $temp;
        }

        $this->value = $this->_trim($this->value);
    }

    /**
     * Normalize
     *
     * Removes leading zeros and truncates (if necessary) to maintain the appropriate precision
     *
     * @param Math\BigInteger
     * @return Math\BigInteger
     * @see _trim()
     * @access private
     */
    private function _normalize($result)
    {
        $result->precision = $this->precision;
        $result->bitmask = $this->bitmask;

        switch ( $this->mode ) {
            case BigInteger::MODE_GMP:
                if (!empty($result->bitmask->value)) {
                    $result->value = gmp_and($result->value, $result->bitmask->value);
                }

                return $result;
            case BigInteger::MODE_BCMATH:
                if (!empty($result->bitmask->value)) {
                    $result->value = bcmod($result->value, $result->bitmask->value);
                }

                return $result;
        }

        $value = &$result->value;

        if ( !count($value) ) {
            return $result;
        }

        $value = $this->_trim($value);

        if (!empty($result->bitmask->value)) {
            $length = min(count($value), count($this->bitmask->value));
            $value = array_slice($value, 0, $length);

            for ($i = 0; $i < $length; ++$i) {
                $value[$i] = $value[$i] & $this->bitmask->value[$i];
            }
        }

        return $result;
    }

    /**
     * Trim
     *
     * Removes leading zeros
     *
     * @param Array $value
     * @return Math\BigInteger
     * @access private
     */
    private function _trim($value)
    {
        for ($i = count($value) - 1; $i >= 0; --$i) {
            if ( $value[$i] ) {
                break;
            }
            unset($value[$i]);
        }

        return $value;
    }

    /**
     * Array Repeat
     *
     * @param $input Array
     * @param $multiplier mixed
     * @return Array
     * @access private
     */
    private function _array_repeat($input, $multiplier)
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
    private function _base256_lshift(&$x, $shift)
    {
        if ($shift == 0) {
            return;
        }

        $num_bytes = $shift >> 3; // eg. floor($shift/8)
        $shift &= 7; // eg. $shift % 8

        $carry = 0;
        for ($i = strlen($x) - 1; $i >= 0; --$i) {
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
    private function _base256_rshift(&$x, $shift)
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
        for ($i = 0; $i < strlen($x); ++$i) {
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
    private function _int2bytes($x)
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
    private function _bytes2int($x)
    {
        $temp = unpack('Nint', str_pad($x, 4, chr(0), STR_PAD_LEFT));
        return $temp['int'];
    }

    /**
     * DER-encode an integer
     *
     * The ability to DER-encode integers is needed to create RSA public keys for use with OpenSSL
     *
     * @see modPow()
     * @access private
     * @param Integer $length
     * @return String
     */
    private function _encodeASN1Length($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }
}
