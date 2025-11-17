<?php

/**
 * SafeBag
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
 * SafeBag
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class SafeBag
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'bagId' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
            'bagValue' => [
                'constant' => 0,
                'optional' => true,
                'explicit' => true,
                'type' => ASN1::TYPE_ANY,
            ],
            // https://www.rfc-editor.org/rfc/rfc7292#section-4.2 defines this as:
            // bagAttributes  SET OF PKCS12Attribute OPTIONAL
            // but PKCS12Attribute and Attribute are basically the same thing so let's just use that one instead
            'bagAttributes' => [
                'optional' => true,
                'implicit' => true,
                'type' => ASN1::TYPE_SET,
                'min' => 1,
                'max' => -1,
                'children' => Attribute::MAP
            ],
        ],
    ];
}
