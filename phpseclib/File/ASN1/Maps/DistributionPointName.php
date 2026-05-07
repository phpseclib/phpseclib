<?php

/**
 * DistributionPointName
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
 * DistributionPointName
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class DistributionPointName
{
    public const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            'fullName' => [
                'constant' => 0,
                'optional' => true,
                'implicit' => true,
            ] + GeneralNames::MAP,
            'nameRelativeToCRLIssuer' => [
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ] + RelativeDistinguishedName::MAP,
        ],
    ];
}
