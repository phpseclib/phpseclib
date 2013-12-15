<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Math_EcFpCurvePointFactory
{
	protected $curve;

	public function __construct(Math_EcFpCurve $curve)
	{
		$this->curve = $curve;
	}

	/**
	* Octet-String-to-Elliptic-Curve-Point Conversion
	*
	* @param string $data  Bytes
	*
	* @return mixed        False on error, Math_EcFpCurvePoint otherwise.
	*/
	public function fromBytes($data)
	{
		$data_length = strlen($data);

		if ($data_length === 1 && $data === chr(0)) {
			// Point at infinity
			return new Math_EcFpCurvePoint($this->curve);
		}

		$prime_length = strlen($this->curve->getPrime()->toBytes());

		if ($data_length === $prime_length + 1) {

			// Compressed point
			$y_bytes = substr($data, 0, 1);

			$x = new Math_BigInteger(substr($data, 1, $prime_length), 256);

			// alpha = x^3 + a * x + b (mod p)
			$alpha = $this->curve->modPrime(
				$x->multiply($x)->multiply($x)
				->add($this->curve->getA()->multiply($x))
				->add($this->curve->getB())
			);

			user_error("Houston, We've Got a Problem");
			// Find square root beta of alpha modulo p.
			return false;

		} else if ($data_length === 2 * $prime_length + 1) {

			// Uncompressed point
			$type = substr($data, 0, 1);

			if ($type !== chr(4)) {
				return false;
			}

			$point = new Math_EcFpCurvePoint(
				$this->curve,
				new Math_BigInteger(substr($data, 1, $prime_length), 256),
				new Math_BigInteger(substr($data, 1 + $prime_length), 256)
			);

			if (!$this->curve->contains($point)) {
				return false;
			}

			return $point;

		} else {

			return false;

		}
	}
}
