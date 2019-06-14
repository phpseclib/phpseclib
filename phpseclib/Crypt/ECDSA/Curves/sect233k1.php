<?php

/**
 * sect233k1
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

use phpseclib\Crypt\ECDSA\BaseCurves\Binary;
use phpseclib\Math\BigInteger;

class sect233k1 extends Binary
{
    public function __construct()
    {
        $this->setModulo(233, 74, 0);
        $this->setCoefficients(
            '000000000000000000000000000000000000000000000000000000000000',
            '000000000000000000000000000000000000000000000000000000000001'
        );
        $this->setBasePoint(
            '017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126',
            '01DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3'
        );
        $this->setOrder(new BigInteger('8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF', 16));
    }
}
