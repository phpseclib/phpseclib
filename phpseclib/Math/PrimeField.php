<?php

/**
 * Prime Finite Fields
 *
 * Utilizes the factory design pattern
 *
 * PHP version 5 and 7
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://pear.php.net/package/Math_BigInteger
 */

declare(strict_types=1);

namespace phpseclib3\Math;

use phpseclib3\Math\Common\FiniteField;
use phpseclib3\Math\PrimeField\Integer;

/**
 * Prime Finite Fields
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class PrimeField extends FiniteField
{
    /**
     * Instance Counter
     *
     * @var int
     */
    private static $instanceCounter = 0;

    /**
     * Keeps track of current instance
     *
     * @var int
     */
    protected $instanceID;

    /**
     * Default constructor
     */
    public function __construct(BigInteger $modulo)
    {
        //if (!$modulo->isPrime()) {
        //    throw new \UnexpectedValueException('PrimeField requires a prime number be passed to the constructor');
        //}

        $this->modulo = $modulo;

        $this->instanceID = self::$instanceCounter++;
        Integer::setModulo($this->instanceID, $modulo);
        Integer::setRecurringModuloFunction($this->instanceID, $modulo->createRecurringModuloFunction());
    }

    /**
     * Use a custom defined modular reduction function
     */
    public function setReduction(\Closure $func): void
    {
        $this->reduce = $func->bindTo($this, $this);
    }

    /**
     * Returns an instance of a dynamically generated PrimeFieldInteger class
     */
    public function newInteger(BigInteger $num): Integer
    {
        return new Integer($this->instanceID, $num);
    }

    /**
     * Returns an integer on the finite field between one and the prime modulo
     */
    public function randomInteger(): Integer
    {
        static $one;
        if (!isset($one)) {
            $one = new BigInteger(1);
        }

        return new Integer($this->instanceID, BigInteger::randomRange($one, Integer::getModulo($this->instanceID)));
    }

    /**
     * Returns the length of the modulo in bytes
     */
    public function getLengthInBytes(): int
    {
        return Integer::getModulo($this->instanceID)->getLengthInBytes();
    }

    /**
     * Returns the length of the modulo in bits
     */
    public function getLength(): int
    {
        return Integer::getModulo($this->instanceID)->getLength();
    }

    /**
     *  Destructor
     */
    public function __destruct()
    {
        Integer::cleanupCache($this->instanceID);
    }
}
