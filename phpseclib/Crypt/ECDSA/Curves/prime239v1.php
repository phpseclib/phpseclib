<?php

/**
 * prime239v1
 *
 * PHP version 5 and 7
 *
 * @category  Crypt
 * @package   ECDSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://pear.php.net/package/Math_BigInteger
 */

namespace phpseclib\Crypt\ECDSA\Curves;

use phpseclib\Crypt\ECDSA\BaseCurves\Prime;
use phpseclib\Math\BigInteger;

class prime239v1 extends Prime
{
    public function __construct()
    {
        $this->setModulo(new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF', 16));
        $this->setCoefficients(
            new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC', 16),
            new BigInteger('6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A', 16)
        );
        $this->setBasePoint(
            new BigInteger('0FFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF', 16),
            new BigInteger('7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE', 16)
        );
        $this->setOrder(new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B', 16));
    }
}