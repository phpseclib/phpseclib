<?php

/**
 * ReadBytes trait
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\System\SSH\Common\Traits;

/**
 * ReadBytes trait
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
trait ReadBytes
{
    /**
     * Read data
     *
     * @throws \RuntimeException on connection errors
     */
    public function readBytes(int $length): string
    {
        $temp = fread($this->fsock, $length);
        if ($temp === false) {
            throw new \phpseclib3\Exception\RuntimeException('\fread() failed.');
        }
        if (strlen($temp) !== $length) {
            throw new \phpseclib3\Exception\RuntimeException("Expected $length bytes; got " . strlen($temp));
        }
        return $temp;
    }
}
