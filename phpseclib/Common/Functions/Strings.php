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

use phpseclib\Math\BigInteger;

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

    /**
     * Performs blinded equality testing on strings
     *
     * Protects against a particular type of timing attack described.
     *
     * See {@link http://codahale.com/a-lesson-in-timing-attacks/ A Lesson In Timing Attacks (or, Don't use MessageDigest.isEquals)}
     *
     * Thanks for the heads up singpolyma!
     *
     * @access public
     * @param string $x
     * @param string $y
     * @return bool
     */
    public static function equals($x, $y)
    {
        if (strlen($x) != strlen($y)) {
            return false;
        }

        $result = 0;
        for ($i = 0, $iMax = strlen($x); $i < $iMax; $i++) {
            $result |= ord($x[$i]) ^ ord($y[$i]);
        }

        return $result == 0;
    }

    /**
     * Parse SSH2-style string
     *
     * Returns either an array or a boolean if $data is malformed.
     *
     * Valid characters for $format are as follows:
     *
     * C = byte
     * b = boolean (true/false)
     * N = uint32
     * s = string
     * i = mpint
     * l = name-list
     *
     * uint64 is not supported.
     *
     * @param string $format
     * @param $data
     * @return mixed
     * @access public
     * @throws \InvalidArgumentException
     */
    public static function unpackSSH2($format, $data)
    {
        $result = [];
        for ($i = 0, $iMax = strlen($format); $i < $iMax; $i++) {
            switch ($format[$i]) {
                case 'C':
                case 'b':
                    if (!strlen($data)) {
                        return false;
                    }
                    break;
                case 'N':
                case 'i':
                case 's':
                case 'l':
                    if (strlen($data) < 4) {
                        return false;
                    }
                    break;
                default:
                    throw new \InvalidArgumentException('$format contains an invalid character');
            }
            switch ($format[$i]) {
                case 'C':
                    $result[] = ord(self::shift($data));
                    continue 2;
                case 'b':
                    $result[] = ord(self::shift($data)) != 0;
                    continue 2;
                case 'N':
                    list(, $temp) = unpack('N', self::shift($data, 4));
                    $result[] = $temp;
                    continue 2;
            }
            list(, $length) = unpack('N', self::shift($data, 4));
            if (strlen($data) < $length) {
                return false;
            }
            $temp = self::shift($data, $length);
            switch ($format[$i]) {
                case 'i':
                    $result[] = new BigInteger($temp, -256);
                    break;
                case 's':
                    $result[] = $temp;
                    break;
                case 'l':
                    $result[] = explode(',', $temp);
            }
        }

        return $result;
    }

    /**
     * Create SSH2-style string
     *
     * @param $elements []
     * @access public
     * @return mixed
     * @throws \InvalidArgumentException
     */
    public static function packSSH2(...$elements)
    {
        $format = $elements[0];
        array_shift($elements);
        if (strlen($format) != count($elements)) {
            throw new \InvalidArgumentException('There must be as many arguments as there are characters in the $format string');
        }
        $result = '';
        for ($i = 0, $iMax = strlen($format); $i < $iMax; $i++) {
            $element = $elements[$i];
            switch ($format[$i]) {
                case 'C':
                    if (!is_int($element)) {
                        throw new \InvalidArgumentException('Bytes must be represented as an integer between 0 and 255, inclusive.');
                    }
                    $result.= pack('C', $element);
                    break;
                case 'b':
                    if (!is_bool($element)) {
                        throw new \InvalidArgumentException('A boolean parameter was expected.');
                    }
                    $result.= $element ? "\1" : "\0";
                    break;
                case 'N':
                    if (!is_int($element)) {
                        throw new \InvalidArgumentException('An integer was expected.');
                    }
                    $result.= pack('N', $element);
                    break;
                case 's':
                    if (!is_string($element)) {
                        throw new \InvalidArgumentException('A string was expected.');
                    }
                    $result.= pack('Na*', strlen($element), $element);
                    break;
                case 'i':
                    if (!$element instanceof BigInteger) {
                        throw new \InvalidArgumentException('A phpseclib\Math\BigInteger object was expected.');
                    }
                    $element = $element->toBytes(true);
                    $result.= pack('Na*', strlen($element), $element);
                    break;
                case 'l':
                    if (!is_array($element)) {
                        throw new \InvalidArgumentException('An array was expected.');
                    }
                    $element = implode(',', $element);
                    $result.= pack('Na*', strlen($element), $element);
                    break;
                default:
                    throw new \InvalidArgumentException('$format contains an invalid character');
            }
        }
        return $result;
    }
}
