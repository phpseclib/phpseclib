<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Elliptic curve Diffie-Hellman
 */
class Math_EcDH
{
	static protected $one;

	protected $curve;
	protected $curve_bits;

	protected $private_multiplier;
	protected $shared_point;

	public function __construct(Math_EcFpCurveFactory $factory, $kex_algorithm)
	{
		$curve_name = substr($kex_algorithm, 10); // strlen('ecdh-sha2-') = 10
		$this->curve = $factory->fromNistName($curve_name);

		if (!$this->curve) {
			user_error("Could not find a curve associated with kex algorithm $kex_algorithm.");
			return false;
		}

		// $curve_bits = strlen($this->curve->getPrime()->toBits());
		$this->curve_bits = (int) substr($curve_name, 5); // strlen('nistp') = 5

		if (is_null(self::$one)) {
			self::$one = new Math_BigInteger(1);
		}
	}

	/**
	* @return Math_EcFpCurve
	*/
	public function getCurve()
	{
		return $this->curve;
	}

	/**
	* @return Math_BigInteger
	*/
	public function getPrivateKey()
	{
		return $this->private_multiplier;
	}

	/**
	* @return null
	*/
	public function generatePrivateKey()
	{
		$this->private_multiplier = self::$one->random(
			self::$one,
			$this->curve->getOrder()->subtract(self::$one)
		);
	}

	/**
	* @return Math_EcFpCurvePoint
	*/
	public function getPublicPoint()
	{
		if (!$this->private_multiplier) {
			$this->generatePrivateKey();
		}

		return $this->curve->getGenerator()->multiply($this->private_multiplier);
	}

	/**
	* @return Math_EcFpCurvePoint
	*/
	public function agreeWith(Math_EcFpCurvePoint $their_public_point)
	{
		// This is supposed to be cofactor multiplication elliptic curve
		// diffie-hellman, but because the cofactor of all supported curves is
		// 1, cofactor multiplication is not done. If cofactor multiplication
		// is to be supported with cofactor != 1, just multiply the private
		// multiplier with the cofactor of the curve before performing the
		// point multiplication.
		return $this->shared_point = $their_public_point->multiply($this->private_multiplier);
	}

	/**
	* @return Math_EcFpCurvePoint
	*/
	public function getSharedPoint()
	{
		return $this->shared_point;
	}

	/**
	* @return string
	*/
	public function getHash()
	{
		// RFC5656 page 11
		switch (true) {
			case $this->curve_bits <= 256:
				return 'sha256';
			case $this->curve_bits <= 384:
				return 'sha384';
			default:
				return 'sha512';
		}
	}
}
