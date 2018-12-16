<?php

/**
 * Binary Finite Fields
 *
 * In a binary finite field numbers are actually polynomial equations. If you
 * represent the number as a sequence of bits you get a sequence of 1's or 0's.
 * These 1's or 0's represent the coefficients of the x**n, where n is the
 * location of the given bit. When you add numbers over a binary finite field
 * the result should have a coefficient of 1 or 0 as well. Hence addition
 * and subtraction become the same operation as XOR, etc.
 *
 * PHP version 5 and 7
 *
 * @category  Math
 * @package   BigInteger
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib\Math\BinaryField;

use phpseclib\Math\Common\FiniteField\Integer as Base;
use phpseclib\Math\BigInteger;
use phpseclib\Math\BinaryField;
use ParagonIE\ConstantTime\Hex;

/**
 * Binary Finite Fields
 *
 * @package Math
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class Integer extends Base
{
    /**
     * Holds the BinaryField's value
     *
     * @var string
     */
    protected $value;

    /**
     * Keeps track of current instance
     *
     * @var int
     */
    protected $instanceID;

    /**
     * Holds the PrimeField's modulo
     *
     * @var string[]
     */
    protected static $modulo;

    /**
     * Holds a pre-generated function to perform modulo reductions
     *
     * @var callable[]
     */
    protected static $reduce;

    /**
     * Default constructor
     */
    public function __construct($instanceID, $num = '')
    {
        $this->instanceID = $instanceID;
        if (!strlen($num)) {
            $this->value = '';
        } else {
            $reduce = static::$reduce[$instanceID];
            $this->value = $reduce($num);
        }
    }

    /**
     * Set the modulo for a given instance
     */
    public static function setModulo($instanceID, $modulo)
    {
        static::$modulo[$instanceID] = $modulo;
    }

    /**
     * Set the modulo for a given instance
     */
    public static function setRecurringModuloFunction($instanceID, callable $function)
    {
        static::$reduce[$instanceID] = $function;
    }

    /**
     * Tests a parameter to see if it's of the right instance
     *
     * Throws an exception if the incorrect class is being utilized
     */
    private static function checkInstance(self $x, self $y)
    {
        if ($x->instanceID != $y->instanceID) {
            throw new \UnexpectedValueException('The instances of the two BinaryField\Integer objects do not match');
        }
    }

    /**
     * Tests the equality of two numbers.
     *
     * @return bool
     */
    public function equals(self $x)
    {
        static::checkInstance($this, $x);

        return $this->value == $x->value;
    }

    /**
     * Compares two numbers.
     *
     * @return int
     */
    public function compare(self $x)
    {
        static::checkInstance($this, $x);

        $a = $this->value;
        $b = $x->value;

        $length = max(strlen($a), strlen($b));

        $a = str_pad($a, $length, "\0", STR_PAD_LEFT);
        $b = str_pad($b, $length, "\0", STR_PAD_LEFT);

        return strcmp($a, $b);
    }

    /**
     * Returns the degree of the polynomial
     *
     * @param string $x
     * @return int
     */
    private static function deg($x)
    {
        $x = ltrim($x, "\0");
        $xbit = decbin(ord($x[0]));
        $xlen = $xbit == '0' ? 0 : strlen($xbit);
        $len = strlen($x);
        if (!$len) {
            return -1;
        }
        return 8 * strlen($x) - 9 + $xlen;
    }

    /**
     * Perform polynomial division
     *
     * @return string[]
     * @link https://en.wikipedia.org/wiki/Polynomial_greatest_common_divisor#Euclidean_division
     */
    private static function polynomialDivide($x, $y)
    {
        if (strcmp($x, str_pad($y, strlen($x), "\0", STR_PAD_LEFT)) < 0) {
            return ['', ltrim($x, "\0")];
        }

        // in wikipedia's description of the algorithm, lc() is the leading coefficient. over a binary field that's
        // always going to be 1.

        $q = chr(0);
        $d = static::deg($y);
        $r = $x;
        while (($degr = static::deg($r)) >= $d) {
            $s = '1' . str_repeat('0', $degr - $d);
            $s = BinaryField::base2ToBase256($s);
            $length = max(strlen($s), strlen($q));
            $q = !isset($q) ? $s :
                str_pad($q, $length, "\0", STR_PAD_LEFT) ^
                str_pad($s, $length, "\0", STR_PAD_LEFT);
            $s = static::polynomialMultiply($s, $y);
            $length = max(strlen($r), strlen($s));
            $r = str_pad($r, $length, "\0", STR_PAD_LEFT) ^
                 str_pad($s, $length, "\0", STR_PAD_LEFT);
        }

        return [ltrim($q, "\0"), ltrim($r, "\0")];
    }

    /**
     * Perform polynomial multiplation
     *
     * @return string[]
     * @link https://en.wikipedia.org/wiki/Finite_field_arithmetic#Multiplication
     */
    private static function polynomialMultiply($x, $y)
    {
        $precomputed = [ltrim($x, "\0")];
        $x = strrev(BinaryField::base256ToBase2($x));
        $y = strrev(BinaryField::base256ToBase2($y));
        if (strlen($x) == strlen($y)) {
            $length = strlen($x);
        } else {
            $length = max(strlen($x), strlen($y));
            $x = str_pad($x, $length, '0');
            $y = str_pad($y, $length, '0');
        }
        $result = str_repeat('0', 2 * $length - 1);
        $result = BinaryField::base2ToBase256($result);
        $size = strlen($result);
        $x = strrev($x);

        // precompute left shift 1 through 7
        for ($i = 1; $i < 8; $i++) {
            $precomputed[$i] = BinaryField::base2ToBase256($x . str_repeat('0', $i));
        }
        for ($i = 0; $i < strlen($y); $i++) {
            if ($y[$i] == '1') {
                $temp = $precomputed[$i & 7] . str_repeat("\0", $i >> 3);
                $result^= str_pad($temp, $size, "\0", STR_PAD_LEFT);
            }
        }

        return $result;
    }

    /**
     * Adds two BinaryFieldIntegers.
     *
     * @return static
     */
    public function add(self $y)
    {
        static::checkInstance($this, $y);

        $length = strlen(static::$modulo[$this->instanceID]);

        $x = str_pad($this->value, $length, "\0", STR_PAD_LEFT);
        $y = str_pad($y->value, $length, "\0", STR_PAD_LEFT);

        return new static($this->instanceID, $x ^ $y);
    }

    /**
     * Subtracts two BinaryFieldIntegers.
     *
     * @return static
     */
    public function subtract(self $x)
    {
        return $this->add($x);
    }

    /**
     * Multiplies two BinaryFieldIntegers.
     *
     * @return static
     */
    public function multiply(self $y)
    {
        static::checkInstance($this, $y);

        return new static($this->instanceID, static::polynomialMultiply($this->value, $y->value));
    }

    /**
     * Returns the modular inverse of a BinaryFieldInteger
     *
     * @return static
     */
    public function modInverse()
    {
        $remainder0 = static::$modulo[$this->instanceID];
        $remainder1 = $this->value;

        if ($remainder1 == '') {
            return new static($this->instanceID);
        }

        $aux0 = "\0";
        $aux1 = "\1";
        while ($remainder1 != "\1") {
            list($q, $r) = static::polynomialDivide($remainder0, $remainder1);
            $remainder0 = $remainder1;
            $remainder1 = $r;
            // the auxiliary in row n is given by the sum of the auxiliary in
            // row n-2 and the product of the quotient and the auxiliary in row
            // n-1
            $temp = static::polynomialMultiply($aux1, $q);
            $aux = str_pad($aux0, strlen($temp), "\0", STR_PAD_LEFT) ^ $temp;
            $aux0 = $aux1;
            $aux1 = $aux;
        }

        $temp = new static($this->instanceID);
        $temp->value = $aux1;
        return $temp;
    }

    /**
     * Divides two PrimeFieldIntegers.
     *
     * @return static
     */
    public function divide(self $x)
    {
        static::checkInstance($this, $x);

        $x = $x->modInverse();
        return $this->multiply($x);
    }

    /**
     * Negate
     *
     * A negative number can be written as 0-12. With modulos, 0 is the same thing as the modulo
     * so 0-12 is the same thing as modulo-12
     *
     * @return object
     */
    public function negate()
    {
        $x = str_pad($this->value, strlen(static::$modulo[$this->instanceID]), "\0", STR_PAD_LEFT);

        return new static($x ^ static::$modulo[$this->instanceID]);
    }

    /**
     * Returns the modulo
     *
     * @return integer
     */
    public static function getModulo($instanceID)
    {
        return static::$modulo[$instanceID];
    }

    /**
     * Converts an Integer to a byte string (eg. base-256).
     *
     * @return string
     */
    public function toBytes()
    {
        return str_pad($this->value, strlen(static::$modulo[$this->instanceID]), "\0", STR_PAD_LEFT);
    }

    /**
     * Converts an Integer to a hex string (eg. base-16).
     *
     * @return string
     */
    public function toHex()
    {
        return Hex::encode($this->toBytes());
    }

    /**
     * Converts an Integer to a bit string (eg. base-2).
     *
     * @return string
     */
    public function toBits()
    {
        //return str_pad(BinaryField::base256ToBase2($this->value), strlen(static::$modulo[$this->instanceID]), '0', STR_PAD_LEFT);
        return BinaryField::base256ToBase2($this->value);
    }

    /**
     * Converts an Integer to a BigInteger
     *
     * @return string
     */
    public function toBigInteger()
    {
        return new BigInteger($this->value, 256);
    }

    /**
     *  __toString() magic method
     *
     * @access public
     */
    public function __toString()
    {
        return (string) $this->toBigInteger();
    }

    /**
     *  __debugInfo() magic method
     *
     * @access public
     */
    public function __debugInfo()
    {
        return ['value' => $this->toHex()];
    }
}