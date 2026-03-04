<?php

/**
 * SignerIdentifier
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
 * SignerIdentifier
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class SignerIdentifier
{
    public const MAP = [
        'type' => ASN1::TYPE_CHOICE,
        'children' => [
            'issuerAndSerialNumber' => IssuerAndSerialNumber::MAP,
            'subjectKeyIdentifier' => [
                'constant' => 0,
                'optional' => true,
                'explicit' => true,
            ] + SubjectKeyIdentifier::MAP,
        ],
    ];
}
