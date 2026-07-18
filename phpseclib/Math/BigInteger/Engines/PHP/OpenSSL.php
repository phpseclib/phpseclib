<?php

/**
 * OpenSSL Modular Exponentiation Engine
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\Math\BigInteger\Engines\PHP;

use phpseclib4\Math\BigInteger\Engines\OpenSSL as Progenitor;

/**
 * OpenSSL Modular Exponentiation Engine
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @psalm-api
 */
abstract class OpenSSL extends Progenitor
{
}
