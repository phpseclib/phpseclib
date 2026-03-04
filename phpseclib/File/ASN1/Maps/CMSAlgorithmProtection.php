<?php

/**
 * CMSAlgorithmProtection
 *
 * From RFC6211
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
 * CMSAlgorithmProtection
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class CMSAlgorithmProtection
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'digestAlgorithm' => DigestAlgorithmIdentifier::MAP,
            'signatureAlgorithm' => [
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ] + SignatureAlgorithmIdentifier::MAP,
            'macAlgorithm' => [
                'constant' => 2,
                'optional' => true,
                'implicit' => true,
            ] + MessageAuthenticationCodeAlgorithm::MAP,
        ],
    ];
}