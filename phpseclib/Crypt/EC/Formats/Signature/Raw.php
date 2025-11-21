<?php

/**
 * Raw EC Signature Handler
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\EC\Formats\Signature;

use phpseclib4\Crypt\Common\Formats\Signature\Raw as Progenitor;

/**
 * Raw DSA Signature Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Raw extends Progenitor
{
}
