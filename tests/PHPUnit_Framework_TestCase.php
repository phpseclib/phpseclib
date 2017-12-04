<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use PHPUnit\Framework\TestCase;

abstract class PHPUnit_Framework_TestCase extends PHPUnit\Framework\TestCase
{
    public function getMock($className, $methodName)
    {
        return $this->getMockBuilder($className)->setMethods($methodName)->getMock();
    }
}
