<?php

/**
 * Built-In BCMath Modular Exponentiation Engine
 *
 * PHP version 5 and 7
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://pear.php.net/package/Math_BigInteger
 */

declare(strict_types=1);

namespace phpseclib3\Math\BigInteger\Engines\BCMath;

use phpseclib3\Math\BigInteger\Engines\BCMath;

/**
 * Built-In BCMath Modular Exponentiation Engine
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class BuiltIn extends BCMath
{
    /**
     * Performs modular exponentiation.
     */
    protected static function powModHelper(BCMath $x, BCMath $e, BCMath $n): BCMath
    {
        $temp = new BCMath();
        $temp->value = bcpowmod($x->value, $e->value, $n->value);

        return $x->normalize($temp);
    }
}
