<?php

/**
 * DerivableKey interface
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\CMS\EnvelopedData;

/**
 * DerivableKey interface
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
interface DerivableKey
{
    public function decrypt(): string;
}
