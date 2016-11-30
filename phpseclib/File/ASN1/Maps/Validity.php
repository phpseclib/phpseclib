<?php

/**
 * Validity
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

namespace phpseclib\File\ASN1\Maps;

use phpseclib\File\ASN1;

/**
 * Validity
 *
 * @package ASN1
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class Validity
{
    const MAP = [
        'type'     => ASN1::TYPE_SEQUENCE,
        'children' => [
            'notBefore' => Time::MAP,
            'notAfter'  => Time::MAP
        ]
    ];
}
