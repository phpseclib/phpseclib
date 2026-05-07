<?php

/**
 * NoticeReference
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Maps;

use phpseclib4\File\ASN1;

/**
 * NoticeReference
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class NoticeReference
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'organization' => DisplayText::MAP,
            'noticeNumbers' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'min' => 1,
                'max' => 200,
                'children' => ['type' => ASN1::TYPE_INTEGER],
            ],
        ],
    ];
}
