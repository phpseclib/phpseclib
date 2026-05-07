<?php

/**
 * RevocationInfoChoice
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
 * RevocationInfoChoice
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class RevocationInfoChoice
{
    public const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            'crl' => CertificateList::MAP,
            'other' => [
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ] + OtherRevocationInfoFormat::MAP,
        ],
    ];
}
