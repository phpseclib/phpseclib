<?php

/**
 * QcEuLimitValue
 *
 * From https://www.etsi.org/deliver/etsi_ts/101800_101899/101862/01.03.02_60/ts_101862v010302p.pdf
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

/**
 * QcEuLimitValue
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class QcEuLimitValue
{
    public const MAP = MonetaryValue::MAP;
}
