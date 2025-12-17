<?php

/**
 * PKCS12 PBKDF Helper for Symmetric Keys and MACs
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\Common\Traits;

use phpseclib4\Crypt\Hash;
use phpseclib4\Math\BigInteger;

/**
 * PKCS12 PBKDF Helper for Symmetric Keys and MACs
 *
 * Used by PKCS8, PFX and CMS
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
trait PKCS12Helper
{
    /**
     * PKCS#12 KDF Helper Function
     *
     * As discussed here:
     *
     * {@link https://tools.ietf.org/html/rfc7292#appendix-B}
     *
     * @return string $a
     * @see self::setPassword()
     */
    private static function pkcs12helper(int $n, Hash $hashObj, string $i, string $d, int $count): string
    {
        static $one;
        if (!isset($one)) {
            $one = new BigInteger(1);
        }

        $blockLength = $hashObj->getBlockLength() >> 3;

        $c = ceil($n / $hashObj->getLengthInBytes());
        $a = '';
        for ($j = 1; $j <= $c; $j++) {
            $ai = $d . $i;
            for ($k = 0; $k < $count; $k++) {
                $ai = $hashObj->hash($ai);
            }
            $b = '';
            while (strlen($b) < $blockLength) {
                $b .= $ai;
            }
            $b = substr($b, 0, $blockLength);
            $b = new BigInteger($b, 256);
            $newi = '';
            for ($k = 0; $k < strlen($i); $k += $blockLength) {
                $temp = substr($i, $k, $blockLength);
                $temp = new BigInteger($temp, 256);
                $temp->setPrecision($blockLength << 3);
                $temp = $temp->add($b);
                $temp = $temp->add($one);
                $newi .= $temp->toBytes(false);
            }
            $i = $newi;
            $a .= $ai;
        }

        return substr($a, 0, $n);
    }
}