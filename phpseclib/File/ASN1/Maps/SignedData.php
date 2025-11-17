<?php

/**
 * SignedData
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
 * SignedData
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class SignedData
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => CMSVersion::MAP,
            'digestAlgorithms' => DigestAlgorithmIdentifiers::MAP,
            'encapContentInfo' => EncapsulatedContentInfo::MAP,
            'certificates' => [
                'constant' => 0,
                'optional' => true,
                'implicit' => true,
            ] + CertificateSet::MAP,
            'crls' => [
                'constant' => 1,
                'optional' => true,
                'implicit' => true,
            ] + RevocationInfoChoices::MAP,
            'signerInfos' => SignerInfos::MAP,
        ],
    ];
}
