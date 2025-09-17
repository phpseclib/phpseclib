<?php

/**
 * OtherRevocationInfoFormat
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
 * OtherRevocationInfoFormat
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class OtherRevocationInfoFormat
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'otherRevInfoFormat' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
            'otherRevInfo' => ['type' => ASN1::TYPE_ANY],
        ],
    ];
}
