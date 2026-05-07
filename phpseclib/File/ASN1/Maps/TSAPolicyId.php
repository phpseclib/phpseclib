<?php

/**
 * TSAPolicyId
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Maps;

use phpseclib4\File\ASN1;

/**
 * TSAPolicyId
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class TSAPolicyId
{
    public const MAP = ['type' => ASN1::TYPE_OBJECT_IDENTIFIER];
}
