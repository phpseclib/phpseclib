<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Simple wrapper for a two-dimensional point consisting of two BigIntegers.
 */
class Math_BigInteger2dPoint
{
	/**
	* The x-coordinate of the point.
	*
	* @var Math_BigInteger
	*/
	protected $x;

	/**
	* The y-coordinate of the point.
	*
	* @var Math_BigInteger
	*/
	protected $y;

	/**
	* @param Math_BigInteger $x The x-coordinate of the point
	* @param Math_BigInteger $y The y-coordinate of the point
	*/
	function __construct(Math_BigInteger $x, Math_BigInteger $y)
	{
		$this->x = $x;
		$this->y = $y;
	}

	/**
	* Returns the BigInteger of the x-coordinate.
	*
	* @return Math_BigInteger
	*/
	public function getX()
	{
		return $this->x;
	}

	/**
	* Returns the BigInteger of the y-coordinate.
	*
	* @return Math_BigInteger
	*/
	public function getY()
	{
		return $this->y;
	}

	/**
	* Checks whether a given point is equal to this point by comparing the
	* coordinates.
	*
	* @return bool True if the points are equal, false otherwise.
	*/
	public function equals(self $p)
	{
		return
			$this->x->equals($p->getX()) &&
			$this->y->equals($p->getY())
		;
	}
}
