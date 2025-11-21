<?php

/**
 * DirectoryString
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
 * DirectoryString
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class DirectoryString
{
    public const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            'teletexString' => ['type' => ASN1::TYPE_TELETEX_STRING],
            'printableString' => ['type' => ASN1::TYPE_PRINTABLE_STRING],
            'universalString' => ['type' => ASN1::TYPE_UNIVERSAL_STRING],
            'utf8String' => ['type' => ASN1::TYPE_UTF8_STRING],
            'bmpString' => ['type' => ASN1::TYPE_BMP_STRING],
        ],
    ];
}
