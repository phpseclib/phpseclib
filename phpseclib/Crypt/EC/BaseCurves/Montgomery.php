<?php

/**
 * Curves over y^2 = x^3 + a*x + x
 *
 * Technically, a Montgomery curve has a coefficient for y^2 but for Curve25519 and Curve448 that
 * coefficient is 1.
 *
 * Curve25519 and Curve448 do not make use of the y coordinate, which makes it unsuitable for use
 * with ECDSA / EdDSA. A few other differences between Curve25519 and Ed25519 are discussed at
 * https://crypto.stackexchange.com/a/43058/4520
 *
 * More info:
 *
 * https://en.wikipedia.org/wiki/Montgomery_curve
 *
 * PHP version 5 and 7
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2019 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://pear.php.net/package/Math_BigInteger
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\EC\BaseCurves;

use phpseclib4\Crypt\EC\Curves\Curve25519;
use phpseclib4\Exception\{InvalidStateException, UnsupportedValueException};
use phpseclib4\Math\{BigInteger, PrimeField};
use phpseclib4\Math\PrimeField\Integer as PrimeInteger;

/**
 * Curves over y^2 = x^3 + a*x + x
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class Montgomery extends Base
{
    /**
     * Prime Field Integer factory
     */
    protected PrimeField $factory;

    /**
     * Cofficient for x
     */
    protected PrimeInteger $a;

    /**
     * Constant used for point doubling
     */
    protected PrimeInteger $a24;

    /**
     * The Number Zero
     */
    protected PrimeInteger $zero;

    /**
     * The Number One
     */
    protected PrimeInteger $one;

    /**
     * Base Point
     */
    protected array $p;

    /**
     * The modulo
     */
    protected BigInteger $modulo;

    /**
     * The Order
     */
    protected BigInteger $order;

    /**
     * Sets the modulo
     */
    public function setModulo(BigInteger $modulo): void
    {
        $this->modulo = $modulo;
        $this->factory = new PrimeField($modulo);
        $this->zero = $this->factory->newInteger(new BigInteger());
        $this->one = $this->factory->newInteger(new BigInteger(1));
    }

    /**
     * Set coefficients a
     */
    public function setCoefficients(BigInteger $a): void
    {
        if (!isset($this->factory)) {
            throw new InvalidStateException('setModulo needs to be called before this method');
        }
        $this->a = $this->factory->newInteger($a);
        $two = $this->factory->newInteger(new BigInteger(2));
        $four = $this->factory->newInteger(new BigInteger(4));
        $this->a24 = $this->a->subtract($two)->divide($four);
    }

    /**
     * Set x and y coordinates for the base point
     *
     * @return PrimeInteger[]
     */
    public function setBasePoint(BigInteger|PrimeInteger $x, BigInteger|PrimeInteger $y): array
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
     * Retrieve the base point as an array
     *
     * @return PrimeInteger[]
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
     * Doubles and adds a point on a curve
     *
     * See https://tools.ietf.org/html/draft-ietf-tls-curve25519-01#appendix-A.1.3
     *
     * @return FiniteField[][]
     */
    private function doubleAndAddPoint(array $p, array $q, PrimeInteger $x1): array
    {
        if (!isset($this->factory)) {
            throw new InvalidStateException('setModulo needs to be called before this method');
        }

        if (!count($p) || !count($q)) {
            return [];
        }

        if (!isset($p[1])) {
            throw new UnsupportedValueException('Affine coordinates need to be manually converted to XZ coordinates');
        }

        [$x2, $z2] = $p;
        [$x3, $z3] = $q;

        $a = $x2->add($z2);
        $aa = $a->multiply($a);
        $b = $x2->subtract($z2);
        $bb = $b->multiply($b);
        $e = $aa->subtract($bb);
        $c = $x3->add($z3);
        $d = $x3->subtract($z3);
        $da = $d->multiply($a);
        $cb = $c->multiply($b);
        $temp = $da->add($cb);
        $x5 = $temp->multiply($temp);
        $temp = $da->subtract($cb);
        $z5 = $x1->multiply($temp->multiply($temp));
        $x4 = $aa->multiply($bb);
        $temp = static::class == Curve25519::class ? $bb : $aa;
        $z4 = $e->multiply($temp->add($this->a24->multiply($e)));

        return [
            [$x4, $z4],
            [$x5, $z5],
        ];
    }

    /**
     * Multiply a point on the curve by a scalar
     *
     * Uses the montgomery ladder technique as described here:
     *
     * https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Montgomery_ladder
     * https://github.com/phpecc/phpecc/issues/16#issuecomment-59176772
     */
    public function multiplyPoint(array $p, BigInteger $d): array
    {
        $p1 = [$this->one, $this->zero];
        $alreadyInternal = isset($p[1]);
        $p2 = $this->convertToInternal($p);
        $x = $p[0];

        $b = $d->toBits();
        $b = str_pad($b, 256, '0', STR_PAD_LEFT);
        for ($i = 0; $i < strlen($b); $i++) {
            $b_i = (int) $b[$i];
            if ($b_i) {
                [$p2, $p1] = $this->doubleAndAddPoint($p2, $p1, $x);
            } else {
                [$p1, $p2] = $this->doubleAndAddPoint($p1, $p2, $x);
            }
        }

        return $alreadyInternal ? $p1 : $this->convertToAffine($p1);
    }

    /**
     * Converts an affine point to an XZ coordinate
     *
     * From https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html
     *
     * XZ coordinates represent x y as X Z satsfying the following equations:
     *
     *   x=X/Z
     *
     * @return PrimeInteger[]
     */
    public function convertToInternal(array $p): array
    {
        if (empty($p)) {
            return [clone $this->zero, clone $this->one];
        }

        if (isset($p[1])) {
            return $p;
        }

        $p[1] = clone $this->one;

        return $p;
    }

    /**
     * Returns the affine point
     *
     * @return PrimeInteger[]
     */
    public function convertToAffine(array $p): array
    {
        if (!isset($p[1])) {
            return $p;
        }
        [$x, $z] = $p;
        return [$x->divide($z)];
    }
}
