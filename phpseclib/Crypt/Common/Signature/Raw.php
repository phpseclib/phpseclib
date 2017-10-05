<?php

/**
 * Raw Signature Handler
 *
 * PHP version 5
 *
 * Handles signatures as arrays
 *
 * @category  Crypt
 * @package   Common
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\Common\Signature;

use phpseclib\Math\BigInteger;

/**
 * Raw Signature Handler
 *
 * @package Common
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class Raw
{
    /**
     * Loads a signature
     *
     * @access public
     * @param array $sig
     * @return array|bool
     */
    public static function load($sig)
    {
        switch (true) {
            case !is_array($sig):
            case !isset($sig['r']) || !isset($sig['s']):
            case !$sig['r'] instanceof BigInteger:
            case !$sig['s'] instanceof BigInteger:
                return false;
        }

        return [
            'r' => $sig['r'],
            's' => $sig['s']
        ];
    }

    /**
     * Returns a signature in the appropriate format
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $r
     * @param \phpseclib\Math\BigInteger $s
     * @return string
     */
    public static function save(BigInteger $r, BigInteger $s)
    {
        return compact('r', 's');
    }
}
