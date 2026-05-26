<?php

/**
 * BCMath64 BigInteger Engine
 *
 * Unlike PHP32 and PHP64, BCMath and BCMath64 are both internally represented the same way.
 * What this means is that you can add an instance of BCMath to BCMath64 and vice versa.
 *
 * The main reason a BCMath64 class exists is because 64-bit integers can convert to and from
 * base-256 faster than 32-bit integers.
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\Math\BigInteger\Engines;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Exception\BadConfigurationException;

/**
 * BCMath64 Engine.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class BCMath64 extends BCMath
{
    /**
     * Test for engine validity
     *
     * @see parent::__construct()
     */
    public static function isValidEngine(): bool
    {
        return PHP_INT_SIZE === 8 && extension_loaded('bcmath');
    }

    /**
     * Initialize a BCMath BigInteger Engine instance
     *
     * @see parent::__construct()
     */
    protected function initialize(int $base): void
    {
        if (abs($base) != 256) {
            parent::initialize($base);
            return;
        }

        // round $len to the nearest 8
        $len = (strlen($this->value) + 7) & ~7;

        $x = str_pad($this->value, $len, chr(0), STR_PAD_LEFT);

        $this->value = '0';
        for ($i = 0; $i < $len; $i += 8) {
            $this->value = bcmul($this->value, '18446744073709551616', 0); // 18446744073709551616 == 2**64
            $temp = sprintf('%u', unpack('J', substr($x, $i, 8))[1]);
            $this->value = bcadd($this->value, $temp, 0);
        }
        if ($this->is_negative) {
            $this->value = '-' . $this->value;
        }
    }

    /**
     * Converts a BigInteger to a byte string (eg. base-256).
     */
    public function toBytes(bool $twos_compliment = false): string
    {
        if ($twos_compliment) {
            return $this->toBytesHelper();
        }

        $value = '';
        $current = $this->value;

        if ($current[0] == '-') {
            $current = substr($current, 1);
        }

        while (bccomp($current, '0', 0) > 0) {
            // the following requires PHP 8.4+
            /*
            [$current, $remainder] = bcdivmod($current, '72057594037927936', 0);
            $temp = pack('J', $remainder);
            $value = substr($temp, 1) . $value;
            */
            $quotient = bcdiv($current, '72057594037927936', 0); // 72057594037927936 == 2**56
            $remainder = bcsub($current, bcmul($quotient, '72057594037927936', 0), 0);
            $temp = pack('J', $remainder);
            $value = substr($temp, 1) . $value;
            $current = $quotient;
        }

        return $this->precision > 0 ?
            substr(str_pad($value, $this->precision >> 3, chr(0), STR_PAD_LEFT), -($this->precision >> 3)) :
            ltrim($value, chr(0));
    }
}
