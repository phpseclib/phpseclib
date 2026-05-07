<?php

/**
 * ASN.1 BMP String
 *
 * Basic Multilingual Plane of ISO/IEC/ITU 10646-1
 * https://en.wikipedia.org/wiki/Universal_Coded_Character_Set
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2025-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Types;

/**
 * ASN.1 BMP String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class BMPString extends BaseString
{
    public const TYPE = 30;
    protected const SIZE = 2;
}
