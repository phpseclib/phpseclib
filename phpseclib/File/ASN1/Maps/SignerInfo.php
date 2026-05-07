<?php

/**
 * SignerInfo
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
 * SignerInfo
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class SignerInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => CMSVersion::MAP,
            'sid' => SignerIdentifier::MAP,
            'digestAlgorithm' => DigestAlgorithmIdentifier::MAP,
            'signedAttrs' => [
                'constant' => 0,
                'optional' => true,
                'implicit' => true,
            ] + SignedAttributes::MAP,
            'signatureAlgorithm' => SignatureAlgorithmIdentifier::MAP,
            'signature' => SignatureValue::MAP,
            'unsignedAttrs' => [
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ] + UnsignedAttributes::MAP,
        ],
    ];
}
