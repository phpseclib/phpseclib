<?php

/**
 * SMIMECapabilities
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
 * SMIMECapabilities
 *
 * From https://datatracker.ietf.org/doc/html/rfc2985#section-5.6
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class SMIMECapabilities
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'min' => 0,
        'max' => -1,
        'children' => SMIMECapability::MAP,
    ];
}
