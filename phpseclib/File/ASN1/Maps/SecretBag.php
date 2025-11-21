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

namespace phpseclib4\File\ASN1\Maps;

use phpseclib4\File\ASN1;

/**
 * SafeBag
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class SecretBag
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'secretTypeId' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
            'secretValue' => [
                'constant' => 0,
                'optional' => true,
                'explicit' => true,
                'type' => ASN1::TYPE_ANY,
            ],
            /*
            'bagAttributes' => [
                'optional' => true,
                'implicit' => true,
                'type' => ASN1::TYPE_SET,
                'min' => 1,
                'max' => -1,
                'children' => PKCS12Attribute::MAP
            ],
            */
        ],
    ];
}
