<?php

/**
 * PHP Montgomery Modular Exponentiation Engine with interleaved multiplication
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\Math\BigInteger\Engines\PHP\Reductions;

use phpseclib4\Math\BigInteger\Engines\PHP;

/**
 * PHP Montgomery Modular Exponentiation Engine with interleaved multiplication
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @psalm-api
 */
abstract class MontgomeryMult extends Montgomery
{
    /**
     * Montgomery Multiply
     *
     * Interleaves the montgomery reduction and long multiplication algorithms together as described in
     * {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=13 HAC 14.36}
     *
     * @param class-string<PHP> $class
     * @see self::_prepMontgomery()
     * @see self::_montgomery()
     */
    public static function multiplyReduce(array $x, array $y, array $n, string $class): array
    {
        // the following code, although not callable, can be run independently of the above code
        // although the above code performed better in my benchmarks the following could might
        // perform better under different circumstances. in lieu of deleting it it's just been
        // made uncallable

        static $cache = [
            self::VARIABLE => [],
            self::DATA => [],
        ];

        if (($key = array_search($n, $cache[self::VARIABLE])) === false) {
            $key = count($cache[self::VARIABLE]);
            $cache[self::VARIABLE][] = $n;
            $cache[self::DATA][] = self::modInverse67108864($n, $class);
        }

        $size = max(count($x), count($y), count($n));
        $x = array_pad($x, $size, 0);
        $y = array_pad($y, $size, 0);
        $n = array_pad($n, $size, 0);
        $a = [self::VALUE => self::array_repeat(0, $size + 1)];
        for ($i = 0; $i < $size; ++$i) {
            $temp = $a[self::VALUE][0] + $x[$i] * $y[0];
            $temp = $temp - $class::BASE_FULL * ($class::BASE === 26 ? intval($temp / 0x4000000) : ($temp >> 31));
            $temp = $temp * $cache[self::DATA][$key];
            $temp = $temp - $class::BASE_FULL * ($class::BASE === 26 ? intval($temp / 0x4000000) : ($temp >> 31));
            $temp = $class::addHelper($class::regularMultiply([$x[$i]], $y), false, $class::regularMultiply([$temp], $n), false);
            $a = $class::addHelper($a[self::VALUE], false, $temp[self::VALUE], false);
            $a[self::VALUE] = array_slice($a[self::VALUE], 1);
        }
        if (self::compareHelper($a[self::VALUE], false, $n, false) >= 0) {
            $a = $class::subtractHelper($a[self::VALUE], false, $n, false);
        }
        return $a[self::VALUE];
    }
}
