<?php

/**
 * QcEuLimitValue
 *
 * From https://www.etsi.org/deliver/etsi_ts/101800_101899/101862/01.03.02_60/ts_101862v010302p.pdf
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\File\ASN1\Maps;

use phpseclib3\File\ASN1;

/**
 * QcEuLimitValue
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class QcEuLimitValue
{
    public const MAP = MonetaryValue::MAP;
}
