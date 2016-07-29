<?php

/**
 * Common String Methods
 *
 * PHP version 5
 *
 * @category  Common
 * @package   StringMethods
 * @author    Jim Wigginton <terrafrost@php.net>
 * @author    Hans-Juergen Petrich <petrich@tronic-media.com>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Common;

/**
 * Common String Methods
 *
 * @package StringMethods
 * @author  Jim Wigginton <terrafrost@php.net>
 */
trait StringFunctions {
    /**
     * String Shift
     *
     * Inspired by array_shift
     *
     * @param string $string
     * @param int $index
     * @access private
     * @return string
     */
    function _string_shift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }
}
