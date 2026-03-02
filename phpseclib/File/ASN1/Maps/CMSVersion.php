<?php

/**
 * CMSVersion
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Maps;

use phpseclib4\File\ASN1;

/**
 * CMSVersion
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class CMSVersion
{
    public const MAP = [
        'type' => ASN1::TYPE_INTEGER,
        'mapping' => ['v0', 'v1', 'v2', 'v3', 'v4', 'v5'],
    ];
}
