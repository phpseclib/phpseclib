<?php

/**
 * OtherLogotypeInfo
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
 * OtherLogotypeInfo
 *
 * logotypeType is one of id-logo-loyalty, id-logo-background or
 * id-logo-certImage.
 *
 * https://datatracker.ietf.org/doc/html/rfc9399#appendix-A.1
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class OtherLogotypeInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'logotypeType' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
            'info' => LogotypeInfo::MAP,
        ],
    ];
}
