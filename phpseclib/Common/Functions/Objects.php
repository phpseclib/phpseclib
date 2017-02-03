<?php

/**
 * Common Object Functions
 *
 * PHP version 5
 *
 * @category  Common
 * @package   Functions\Objects
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Common\Functions;

/**
 * Common Object Functions
 *
 * @package Functions\Objects
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Objects
{
    /**
     * Accesses a private variable from an object
     *
     * @param Object $obj
     * @param string $var
     * @return mixed
     * @access public
     */
    public static function getVar($obj, $var)
    {
        $reflection = new \ReflectionClass(get_class($obj));
        $prop = $reflection->getProperty($var);
        $prop->setAccessible(true);
        return $prop->getValue($obj);
    }

    /**
     * Sets the value of a private variable in an object
     *
     * @param Object $obj
     * @param string $var
     * @param mixed $val
     * @return mixed
     * @access public
     */
    public static function setVar($obj, $var, $val)
    {
        $reflection = new \ReflectionClass(get_class($obj));
        $prop = $reflection->getProperty($var);
        $prop->setAccessible(true);
        return $prop->setValue($obj, $val);
    }

    /**
     * Accesses a private method from an object
     *
     * @param Object $obj
     * @param string $func
     * @param array $params
     * @return mixed
     * @access public
     */
    public static function callFunc($obj, $func, $params = array())
    {
        $reflection = new \ReflectionClass(get_class($obj));
        $method = $reflection->getMethod($func);
        $method->setAccessible(true);
        return $method->invokeArgs($obj, $params);
    }
}
