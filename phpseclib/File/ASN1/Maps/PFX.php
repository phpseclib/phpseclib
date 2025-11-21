<?php

/**
 * PFX
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
 * PFX
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PFX
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => [
                'type' => ASN1::TYPE_INTEGER,
                'mapping' => [3 => 'v3'],
            ],
            'authSafe' => ContentInfo::MAP,
            'macData' => [
                'optional' => true,
                'implicit' => true,
            ] + MacData::MAP,
        ],
    ];
}
