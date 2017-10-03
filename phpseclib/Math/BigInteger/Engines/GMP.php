<?php

/**
 * GMP BigInteger Engine
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
use phpseclib\Exception\BadConfigurationException;

/**
 * GMP Engine.
 *
 * @package GMP
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class GMP extends Engine
{
    /**
     * Can Bitwise operations be done fast?
     *
     * @see parent::bitwise_leftRotate()
     * @see parent::bitwise_rightRotate()
     * @access protected
     */
    const FAST_BITWISE = true;

    /**
     * Engine Directory
     *
     * @see parent::setModExpEngine
     * @access protected
     */
    const ENGINE_DIR = 'GMP';

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
     * BigInteger(0)
     *
     * @var \phpseclib\Math\BigInteger\Engines\GMP
     */
    protected static $zero;

    /**
     * BigInteger(1)
     *
     * @var \phpseclib\Math\BigInteger\Engines\GMP
     */
    protected static $one;

    /**
     * BigInteger(2)
     *
     * @var \phpseclib\Math\BigInteger\Engines\GMP
     */
    protected static $two;

    /**
     * Primes > 2 and < 1000
     *
     * Unused for GMP Engine
     *
     * @var mixed
     */
    protected static $primes;

    /**
     * Test for engine validity
     *
     * @see parent::__construct()
     * @return bool
     */
    public static function isValidEngine()
    {
        return extension_loaded('gmp');
    }

    /**
     * Default constructor
     *
     * @param $x integer Base-10 number or base-$base number if $base set.
     * @param int $base
     * @see parent::__construct()
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function __construct($x = 0, $base = 10)
    {
        if (!isset(self::$isValidEngine)) {
            self::$isValidEngine = self::isValidEngine();
        }
        if (!self::$isValidEngine) {
            throw new BadConfigurationException('GMP is not setup correctly on this system');
        }

        if ($x instanceof \GMP) {
            $this->value = $x;
            return;
        }

        $this->value = gmp_init(0);

        parent::__construct($x, $base);
    }

    /**
     * Initialize a GMP BigInteger Engine instance
     *
     * @param int $base
     * @see parent::__construct()
     */
    protected function initialize($base)
    {
        switch (abs($base)) {
            case 256:
                $sign = $this->is_negative ? '-' : '';
                $this->value = gmp_init($sign . '0x' . Hex::encode($this->value));
                break;
            case 16:
                $temp = $this->is_negative ? '-0x' . $this->value : '0x' . $this->value;
                $this->value = gmp_init($temp);
                break;
            case 10:
                $this->value = gmp_init(isset($this->value) ? $this->value : '0');
        }
    }

    /**
     * Converts a BigInteger to a base-10 number.
     *
     * @return string
     */
    public function toString()
    {
        return (string) $this->value;
    }

    /**
     * Converts a BigInteger to a byte string (eg. base-256).
     *
     * @param bool $twos_compliment
     * @return string
     */
    function toBytes($twos_compliment = false)
    {
        if ($twos_compliment) {
            return $this->toBytesHelper();
        }

        if (gmp_cmp($this->value, gmp_init(0)) == 0) {
            return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
        }

        $temp = gmp_strval(gmp_abs($this->value), 16);
        $temp = (strlen($temp) & 1) ? '0' . $temp : $temp;
        $temp = Hex::decode($temp);

        return $this->precision > 0 ?
            substr(str_pad($temp, $this->precision >> 3, chr(0), STR_PAD_LEFT), -($this->precision >> 3)) :
            ltrim($temp, chr(0));
    }

    /**
     * Adds two BigIntegers.
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function add(GMP $y)
    {
        $temp = new self();
        $temp->value = $this->value + $y->value;

        return $this->normalize($temp);
    }

    /**
     * Subtracts two BigIntegers.
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function subtract(GMP $y)
    {
        $temp = new self();
        $temp->value = $this->value - $y->value;

        return $this->normalize($temp);
    }

    /**
     * Multiplies two BigIntegers.
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function multiply(GMP $x)
    {
        $temp = new self();
        $temp->value = $this->value * $x->value;

        return $this->normalize($temp);
    }

    /**
     * Divides two BigIntegers.
     *
     * Returns an array whose first element contains the quotient and whose second element contains the
     * "common residue".  If the remainder would be positive, the "common residue" and the remainder are the
     * same.  If the remainder would be negative, the "common residue" is equal to the sum of the remainder
     * and the divisor (basically, the "common residue" is the first positive modulo).
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function divide(GMP $y)
    {
        $quotient = new self();
        $remainder = new self();

        list($quotient->value, $remainder->value) = gmp_div_qr($this->value, $y->value);

        if (gmp_sign($remainder->value) < 0) {
            $remainder->value = $remainder->value + gmp_abs($y->value);
        }

        return [$this->normalize($quotient), $this->normalize($remainder)];
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
    public function compare(GMP $y)
    {
        return gmp_cmp($this->value, $y->value);
    }

    /**
     * Tests the equality of two numbers.
     *
     * If you need to see if one number is greater than or less than another number, use BigInteger::compare()
     *
     * @return bool
     */
    public function equals(GMP $x)
    {
        return $this->value == $x->value;
    }

    /**
     * Calculates modular inverses.
     *
     * Say you have (30 mod 17 * x mod 17) mod 17 == 1.  x can be found using modular inverses.
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP|false
     */
    public function modInverse(GMP $n)
    {
        $temp = new self();
        $temp->value = gmp_invert($this->value, $n->value);

        return $temp->value === false ? false : $this->normalize($temp);
    }

    /**
     * Calculates the greatest common divisor and Bezout's identity.
     *
     * Say you have 693 and 609.  The GCD is 21.  Bezout's identity states that there exist integers x and y such that
     * 693*x + 609*y == 21.  In point of fact, there are actually an infinite number of x and y combinations and which
     * combination is returned is dependent upon which mode is in use.  See
     * {@link http://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity Bezout's identity - Wikipedia} for more information.
     *
     * @param \phpseclib\Math\BigInteger\Engines\GMP $n
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function extendedGCD(GMP $n)
    {
        extract(gmp_gcdext($this->value, $n->value));

        return [
            'gcd' => $this->normalize(new self($g)),
            'x'   => $this->normalize(new self($s)),
            'y'   => $this->normalize(new self($t))
        ];
    }

    /**
     * Calculates the greatest common divisor
     *
     * Say you have 693 and 609.  The GCD is 21.
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function gcd(GMP $n)
    {
        $r = gmp_gcd($this->value, $n->value);
        return $this->normalize(new self($r));
    }

    /**
     * Absolute value.
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     * @access public
     */
    public function abs()
    {
        $temp = new self();
        $temp->value = gmp_abs($this->value);

        return $temp;
    }

    /**
     * Logical And
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function bitwise_and(GMP $x)
    {
        $temp = new self();
        $temp->value = $this->value & $x->value;

        return $this->normalize($temp);
    }

    /**
     * Logical Or
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function bitwise_or(GMP $x)
    {
        $temp = new self();
        $temp->value = $this->value | $x->value;

        return $this->normalize($temp);
    }

    /**
     * Logical Exclusive Or
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function bitwise_xor(GMP $x)
    {
        $temp = new self();
        $temp->value = $this->value ^ $x->value;

        return $this->normalize($temp);
    }

    /**
     * Logical Right Shift
     *
     * Shifts BigInteger's by $shift bits, effectively dividing by 2**$shift.
     *
     * @param int $shift
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function bitwise_rightShift($shift)
    {
        // 0xFFFFFFFF >> 2 == -1 (on 32-bit systems)
        // gmp_init('0xFFFFFFFF') >> 2 == gmp_init('0x3FFFFFFF')

        $temp = new self();
        $temp->value = $this->value >> $shift;

        return $this->normalize($temp);
    }

    /**
     * Logical Left Shift
     *
     * Shifts BigInteger's by $shift bits, effectively multiplying by 2**$shift.
     *
     * @param int $shift
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function bitwise_leftShift($shift)
    {
        $temp = new self();
        $temp->value = $this->value << $shift;

        return $this->normalize($temp);
    }

    /**
     * Performs modular exponentiation.
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function modPow(GMP $e, GMP $n)
    {
        return $this->powModOuter($e, $n);
    }

    /**
     * Performs modular exponentiation.
     *
     * Alias for modPow().
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function powMod(GMP $e, GMP $n)
    {
        return $this->powModOuter($e, $n);
    }

    /**
     * Performs modular exponentiation.
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    protected function powModInner(GMP $e, GMP $n)
    {
        $class = self::$modexpEngine;
        return $class::powModHelper($this, $e, $n);
    }

    /**
     * Normalize
     *
     * Removes leading zeros and truncates (if necessary) to maintain the appropriate precision
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    protected function normalize(GMP $result)
    {
        $result->precision = $this->precision;
        $result->bitmask = $this->bitmask;

        if ($result->bitmask !== false) {
            $result->value = $result->value & $result->bitmask->value;
        }

        return $result;
    }

    /**
     * Performs some post-processing for randomRangePrime
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    protected static function randomRangePrimeInner(Engine $x, Engine $min, Engine $max)
    {
        $p = gmp_nextprime($x->value);

        if ($p <= $max->value) {
            return new self($p);
        }

        if ($min->value != $x->value) {
            $x = new self($x - 1);
        }

        return self::randomRangePrime($min, $x);
    }

    /**
     * Generate a random prime number between a range
     *
     * If there's not a prime within the given range, false will be returned.
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP|false
     */
    public static function randomRangePrime(GMP $min, GMP $max)
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
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public static function randomRange(GMP $min, GMP $max)
    {
        return self::randomRangeHelper($min, $max);
    }

    /**
     * Make the current number odd
     *
     * If the current number is odd it'll be unchanged.  If it's even, one will be added to it.
     *
     * @see self::randomPrime()
     */
    protected function make_odd()
    {
        gmp_setbit($this->value, 0);
    }

    /**
     * Tests Primality
     *
     * @param int $t
     * @return bool
     */
    protected function testPrimality($t)
    {
        return gmp_prob_prime($this->value, $t) != 0;
    }

    /**
     * Calculates the nth root of a biginteger.
     *
     * Returns the nth root of a positive biginteger, where n defaults to 2
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    protected function rootInner($n)
    {
        $root = new self();
        $root->value = gmp_root($this->value, $n);
        return $this->normalize($root);
    }

    /**
     * Performs exponentiation.
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public function pow(GMP $n)
    {
        $temp = new self();
        $temp->value = $this->value ** $n->value;

        return $this->normalize($temp);
    }

    /**
     * Return the minimum BigInteger between an arbitrary number of BigIntegers.
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public static function min(GMP ...$nums)
    {
        return self::minHelper($nums);
    }

    /**
     * Return the maximum BigInteger between an arbitrary number of BigIntegers.
     *
     * @return \phpseclib\Math\BigInteger\Engines\GMP
     */
    public static function max(GMP ...$nums)
    {
        return self::maxHelper($nums);
    }

    /**
     * Tests BigInteger to see if it is between two integers, inclusive
     *
     * @return boolean
     */
    public function between(GMP $min, GMP $max)
    {
        return $this->compare($min) >= 0 && $this->compare($max) <= 0;
    }
}