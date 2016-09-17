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
class Strings
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
    static function shift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }
}
