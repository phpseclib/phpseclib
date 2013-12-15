<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Elliptic curve over a finite field.
 *
 * The Weierstrass equation is y^2 = x^3 + a * x + b (mod p).
 */
class Math_EcFpCurve
{
	/**
	* @var Math_BigInteger
	*/
	protected $prime;

	/**
	* @var Math_BigInteger
	*/
	protected $a;

	/**
	* @var Math_BigInteger
	*/
	protected $b;

	/**
	* @var Math_EcFpCurvePoint
	*/
	protected $generator;

	/**
	* @var Math_BigInteger
	*/
	protected $order;

	/**
	* @var Math_BigInteger
	*/
	protected $cofactor;

	/**
	* @param Math_BigInteger $prime    The prime defining the underlying field.
	* @param Math_BigInteger $a        The a-parameter of the Weierstrass equation defining the curve.
	* @param Math_BigInteger $b        The b-parameter of the Weierstrass equation defining the curve.
	* @param Math_BigInteger $x        The x-coordinate of the base point G generating the cyclic subgroup.
	* @param Math_BigInteger $y        The y-coordinate of the base point G generating the cyclic subgroup.
	* @param Math_BigInteger $order    The order of the base point, i.e. smallest integer such that $order * G = point at infinity.
	* @param Math_BigInteger $cofactor The cofactor, i.e. the ratio of points on the curve and $order.
	*/
	function __construct(
		Math_BigInteger $prime, Math_BigInteger $a, Math_BigInteger $b,
		Math_BigInteger $x, Math_BigInteger $y, Math_BigInteger $order,
		Math_BigInteger $cofactor
	)
	{
		$this->prime = $prime;
		$this->a = $a;
		$this->b = $b;
		$this->generator = new Math_EcFpCurvePoint($this, $x, $y);
		$this->order = $order;
		$this->cofactor = $cofactor;
	}

	/**
	* Returns the prime generating the underlying field.
	*
	* @return Math_BigInteger
	*/
	public function getPrime()
	{
		return $this->prime;
	}

	/**
	* Returns the a-parameter of the Weierstrass equation defining the curve.
	*
	* @return Math_BigInteger
	*/
	public function getA()
	{
		return $this->a;
	}

	/**
	* Returns the b-parameter of the Weierstrass equation defining the curve.
	*
	* @return Math_BigInteger
	*/
	public function getB()
	{
		return $this->b;
	}

	/**
	* @return Math_EcFpCurvePoint 
	*/
	public function getGenerator()
	{
		return $this->generator;
	}

	/**
	* @return Math_BigInteger
	*/
	public function getOrder()
	{
		return $this->order;
	}

	/**
	* @return Math_BigInteger
	*/
	public function getCofactor()
	{
		return $this->order;
	}

	/**
	* Checks whether the Weierstrass equation holds for a given point, i.e.
	* checks whether the given point is on the curve.
	*
	* @return bool True if point is on the curve, otherwise false.
	*/
	public function contains(Math_BigInteger2dPoint $point)
	{
		$x = $point->getX();
		$y = $point->getY();

		$y2 = $y->multiply($y);
		$ax = $this->a->multiply($x);

		$left = $this->modPrime($y2->subtract($ax)->subtract($this->b));
		$x3 = $x->modPow(new Math_BigInteger(3), $this->prime);

		return $left->equals($x3);
	}

	/**
	* Performs a modular reduction using the curve's prime.
	*
	* @param Math_BigInteger $input
	*
	* @return Math_BigInteger
	*/
	public function modPrime(Math_BigInteger $input)
	{
		list(, $r) = $input->divide($this->prime);
		return $r;
	}

	/**
	* Performs a modular reduction using the curve's order.
	*
	* @param Math_BigInteger $input
	*
	* @return Math_BigInteger
	*/
	public function modOrder(Math_BigInteger $input)
	{
		list(, $r) = $input->divide($this->order);
		return $r;
	}

	/**
	* Checks whether another curve is equal to this curve.
	*
	* @return bool
	*/
	/*public function equals(Math_EcFpCurve $curve)
	{
		return
			$this->a->equals($curve->getA()) &&
			$this->b->equals($curve->getB()) &&
			$this->prime->equals($curve->getPrime())
		;
	}*/
}
