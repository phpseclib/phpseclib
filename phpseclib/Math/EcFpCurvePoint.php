<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Point on an elliptic curve over a finite field.
 */
class Math_EcFpCurvePoint extends Math_BigInteger2dPoint
{
	static protected $zero;
	static protected $one;
	static protected $two;
	static protected $three;

	/**
	* Curve this point is (supposed to be) on.
	*
	* @var Math_EcFpCurve
	*/
	protected $curve;

	/**
	* Whether or not this point is the point at infinity.
	*
	* @var bool
	*/
	protected $is_infinity;

	/**
	* Calling the constructor without coordinates creates the point at infinity.
	*
	* @param Math_EcFpCurve $curve  The curve this point is (supposed to be) on.
	* @param Math_BigInteger $x     The x-coordinate of the point
	* @param Math_BigInteger $y     The y-coordinate of the point
	*/
	function __construct(Math_EcFpCurve $curve, Math_BigInteger $x = null, Math_BigInteger $y = null)
	{
		$this->curve = $curve;
		$this->is_infinity = is_null($x);

		if (!$this->is_infinity)
		{
			parent::__construct($x, $y);
		}

		if (is_null(self::$zero))
		{
			self::$zero = new Math_BigInteger(0);
			self::$one = new Math_BigInteger(1);
			self::$two = new Math_BigInteger(2);
			self::$three = new Math_BigInteger(3);
		}
	}

	/**
	* Returns whether or not this point is the point at infinity.
	*
	* @return bool
	*/
	public function isInfinity()
	{
		return $this->is_infinity;
	}

	/**
	* @return bool
	*/
	public function equals(self $p)
	{
		if ($this->isInfinity() || $p->isInfinity())
		{
			// If one of the points claims to be infinity only compare the
			// infinity flag.
			return $this->isInfinity() === $p->isInfinity();
		}

		return parent::equals($p);
	}

	/**
	* @return Math_EcFpCurvePoint
	*/
	public function add(self $p)
	{
		if ($this->isInfinity())
		{
			return $p;
		}
		else if ($p->isInfinity())
		{
			return $this;
		}

		if ($this->equals($p))
		{
			// 3 * x_1^2 + a
			$factor1 = $this->x->multiply($this->x)->multiply(self::$three)->add($this->curve->getA());

			// 2 * y_1
			$factor2 = $this->y->multiply(self::$two);
		}
		else
		{
			// y_2 - y_1
			$factor1 = $p->getY()->subtract($this->y);

			// x_2 - x_1
			$factor2 = $p->getX()->subtract($this->x);
		}

		if ($factor2->equals(self::$zero))
		{
			$m = self::$zero;
		}
		else
		{
			$m = $factor1->multiply($factor2->modInverse($this->curve->getPrime()));
		}

		// x_3 = m^2 - x_1 - x_2
		$x_3 = $this->curve->modPrime($m->multiply($m)->subtract($this->x)->subtract($p->getX()));

		// y_3 = m * (x_1 - x_3) - y_1
		$y_3 = $this->curve->modPrime($m->multiply($this->x->subtract($x_3))->subtract($this->y));

		return new self($this->curve, $x_3, $y_3);
	}

	/**
	* @return Math_EcFpCurvePoint
	*/
	public function subtract(self $p)
	{
		$p_minus = new self(
			$this->curve,
			$p->getX(),
			self::$zero->subtract($p->getY())
		);

		return $this->add($p_minus);
	}

	/**
	* @return Math_EcFpCurvePoint
	*/
	public function multiply(Math_BigInteger $factor)
	{
		if ($this->isInfinity())
		{
			return $this;
		}

		$factor = $this->curve->modOrder($factor);

		if ($factor->equals(self::$one))
		{
			return $this;
		}

		$q = new self($this->curve);

		if ($factor->equals(self::$zero))
		{
			return $q;
		}

		$bitstring = $factor->toBits();
		for ($i = 0, $l = strlen($bitstring); $i < $l; ++$i)
		{
			$q = $q->add($q);

			if ($bitstring[$i])
			{
				$q = $q->add($this);
			}
		}

		return $q;
	}

	/**
	* @param bool $compress Whether or not point compression should be used.
	*
	* @return string
	*/
	public function toBytes()
	{
		if ($this->isInfinity())
		{
			return "\0";
		}

		$bytes_per_coordinate = strlen($this->curve->getPrime()->toBytes());

		$x_bytes = str_pad($this->x->toBytes(), $bytes_per_coordinate, "\0", STR_PAD_LEFT);
		$y_bytes = str_pad($this->y->toBytes(), $bytes_per_coordinate, "\0", STR_PAD_LEFT);

		return "\4" . $x_bytes . $y_bytes;
	}

	public function toString()
	{
		if ($this->isInfinity())
		{
			return 'infinity';
		}

		return sprintf(
			'(x,y): (%s,%s)',
			$this->x->toHex(),
			$this->y->toHex()
		);
	}

	public function __toString()
	{
		return $this->toString();
	}
}
