<?php

/**
 * BCMath Dynamic Barrett Modular Exponentiation Engine
 *
 * PHP version 5 and 7
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://pear.php.net/package/Math_BigInteger
 */

declare(strict_types=1);

namespace phpseclib3\Math\BigInteger\Engines\BCMath\Reductions;

use phpseclib3\Math\BigInteger\Engines\BCMath;
use phpseclib3\Math\BigInteger\Engines\BCMath\Base;

/**
 * PHP Barrett Modular Exponentiation Engine
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class EvalBarrett extends Base
{
    /**
     * Custom Reduction Function
     *
     * @see self::generateCustomReduction
     */
    private static $custom_reduction;

    /**
     * Barrett Modular Reduction
     *
     * This calls a dynamically generated loop unrolled function that's specific to a given modulo.
     * Array lookups are avoided as are if statements testing for how many bits the host OS supports, etc.
     */
    protected static function reduce(string $n, string $m): string
    {
        $inline = self::$custom_reduction;
        return $inline($n);
    }

    /**
     * Generate Custom Reduction
     *
     * @return callable|void
     */
    protected static function generateCustomReduction(BCMath $m, string $class)
    {
        $m_length = strlen($m);

        if ($m_length < 5) {
            $code = 'return self::BCMOD_THREE_PARAMS ? bcmod($x, $n, 0) : bcmod($x, $n);';
            eval('$func = function ($n) { ' . $code . '};');
            self::$custom_reduction = $func;
            return;
        }

        $lhs = '1' . str_repeat('0', $m_length + ($m_length >> 1));
        $u = bcdiv($lhs, $m, 0);
        $m1 = bcsub($lhs, bcmul($u, $m, 0), 0);

        $cutoff = $m_length + ($m_length >> 1);

        $m = "'$m'";
        $u = "'$u'";
        $m1 = "'$m1'";

        $code = '
            $lsd = substr($n, -' . $cutoff . ');
            $msd = substr($n, 0, -' . $cutoff . ');

            $temp = bcmul($msd, ' . $m1 . ', 0);
            $n = bcadd($lsd, $temp, 0);

            $temp = substr($n, 0, ' . (-$m_length + 1) . ');
            $temp = bcmul($temp, ' . $u . ', 0);
            $temp = substr($temp, 0, ' . (-($m_length >> 1) - 1) . ');
            $temp = bcmul($temp, ' . $m . ', 0);

            $result = bcsub($n, $temp, 0);

            if ($result[0] == \'-\') {
                $temp = \'1' . str_repeat('0', $m_length + 1) . '\';
                $result = bcadd($result, $temp, 0);
            }

            while (bccomp($result, ' . $m . ') >= 0) {
                $result = bcsub($result, ' . $m . ', 0);
            }

            return $result;';

        eval('$func = function ($n) { ' . $code . '};');

        self::$custom_reduction = $func;

        return $func;
    }
}
