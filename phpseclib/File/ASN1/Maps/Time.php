<?php

/**
 * Time
 *
 * PHP version 5
 *
 * @category  File
 * @package   ASN1
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\File\ASN1\Maps;

use phpseclib3\File\ASN1;

/**
 * Time
 *
 * @package ASN1
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class Time
{
    const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            'utcTime' => ['type' => ASN1::TYPE_UTC_TIME],
            'generalTime' => ['type' => ASN1::TYPE_GENERALIZED_TIME]
        ]
    ];
}
