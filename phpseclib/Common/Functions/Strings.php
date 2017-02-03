<?php

/**
 * Common String Functions
 *
 * PHP version 5
 *
 * @category  Common
 * @package   Functions\Strings
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Common\Functions;

/**
 * Common String Functions
 *
 * @package Functions\Strings
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Strings
{
    /**
     * String Shift
     *
     * Inspired by array_shift
     *
     * @param string $string
     * @param int $index
     * @access public
     * @return string
     */
    public static function shift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }

    /**
     * String Pop
     *
     * Inspired by array_pop
     *
     * @param string $string
     * @param int $index
     * @access public
     * @return string
     */
    public static function pop(&$string, $index = 1)
    {
        $substr = substr($string, -$index);
        $string = substr($string, 0, -$index);
        return $substr;
    }
}
