<?php

/**
 * Curves over a*x^2 + y^2 = 1 + d*x^2*y^2
 *
 * http://www.secg.org/SEC2-Ver-1.0.pdf provides for curves with custom parameters.
 * ie. the coefficients can be arbitrary set through specially formatted keys, etc.
 * As such, Prime.php is built very generically and it's not able to take full
 * advantage of curves with 0 coefficients to produce simplified point doubling,
 * point addition. Twisted Edwards curves, in contrast, do not have a way, currently,
 * to customize them. As such, we can omit the super generic stuff from this class
 * and let the named curves (Ed25519 and Ed448) define their own custom tailored
 * point addition and point doubling methods.
 *
 * More info:
 *
 * https://en.wikipedia.org/wiki/Twisted_Edwards_curve
 *
 * PHP version 5 and 7
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://pear.php.net/package/Math_BigInteger
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\EC\BaseCurves;

use phpseclib4\Exception\InvalidStateException;
use phpseclib4\Math\{BigInteger, PrimeField};
use phpseclib4\Math\PrimeField\Integer as PrimeInteger;

/**
 * Curves over a*x^2 + y^2 = 1 + d*x^2*y^2
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class TwistedEdwards extends Base
{
    /**
     * The modulo
     */
    protected BigInteger $modulo;

    /**
     * Cofficient for x^2
     */
    protected PrimeInteger $a;

    /**
     * Cofficient for x^2*y^2
     */
    protected PrimeInteger $d;

    /**
     * Base Point
     */
    protected array $p;

    /**
     * The number zero over the specified finite field
     */
    protected PrimeInteger $zero;

    /**
     * The number one over the specified finite field
     */
    protected PrimeInteger $one;

    /**
     * The number two over the specified finite field
     */
    protected PrimeInteger $two;

    /**
     * Sets the modulo
     */
    public function setModulo(BigInteger $modulo): void
    {
        $this->modulo = $modulo;
        $this->factory = new PrimeField($modulo);
        $this->zero = $this->factory->newInteger(new BigInteger(0));
        $this->one = $this->factory->newInteger(new BigInteger(1));
        $this->two = $this->factory->newInteger(new BigInteger(2));
    }

    /**
     * Set coefficients a and b
     */
    public function setCoefficients(BigInteger $a, BigInteger $d): void
    {
        if (!isset($this->factory)) {
            throw new InvalidStateException('setModulo needs to be called before this method');
        }
        $this->a = $this->factory->newInteger($a);
        $this->d = $this->factory->newInteger($d);
    }

    /**
     * Set x and y coordinates for the base point
     */
    public function setBasePoint(BigInteger|PrimeInteger $x, BigInteger|PrimeInteger $y): void
    {
        if (!isset($this->factory)) {
            throw new InvalidStateException('setModulo needs to be called before this method');
        }
        $this->p = [
            $x instanceof BigInteger ? $this->factory->newInteger($x) : $x,
            $y instanceof BigInteger ? $this->factory->newInteger($y) : $y,
        ];
    }

    /**
     * Returns the a coefficient
     */
    public function getA(): PrimeInteger
    {
        return $this->a;
    }

    /**
     * Returns the a coefficient
     */
    public function getD(): PrimeInteger
    {
        return $this->d;
    }

    /**
     * Retrieve the base point as an array
     */
    public function getBasePoint(): array
    {
        if (!isset($this->factory)) {
            throw new InvalidStateException('setModulo needs to be called before this method');
        }
        /*
        if (!isset($this->p)) {
            throw new InvalidStateException('setBasePoint needs to be called before this method');
        }
        */
        return $this->p;
    }

    /**
     * Returns the affine point
     *
     * @return PrimeInteger[]
     */
    public function convertToAffine(array $p): array
    {
        if (!isset($p[2])) {
            return $p;
        }
        [$x, $y, $z] = $p;
        $z = $this->one->divide($z);
        return [
            $x->multiply($z),
            $y->multiply($z),
        ];
    }

    /**
     * Returns the modulo
     */
    public function getModulo(): BigInteger
    {
        return $this->modulo;
    }

    /**
     * Tests whether or not the x / y values satisfy the equation
     */
    public function verifyPoint(array $p): bool
    {
        [$x, $y] = $p;
        $x2 = $x->multiply($x);
        $y2 = $y->multiply($y);

        $lhs = $this->a->multiply($x2)->add($y2);
        $rhs = $this->d->multiply($x2)->multiply($y2)->add($this->one);

        return $lhs->equals($rhs);
    }
}
