<?php

/**
 * PublicKeyInfo
 *
 * PublicKeyInfo and SubjectPublicKeyInfo are pretty much the same. the only difference
 * is that in SubjectPublicKeyInfo (which actually is defined by an RFC - RFC5280) the
 * element names are algorithm and subjectPublicKey whereas in this one they're
 * publicKeyAlgorithm and publicKey. the publicKey bit, in particular, is relevant, because
 * publicKey is also an optional element in OneAsymmetricKey and it just makes life easier
 * to do isset($key['publicKey']) irrespective of which "map" was used to load the key.
 *
 * PublicKeyInfo::MAP is only used in PKCS8.php and it's children classes
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
 * PublicKeyInfo
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PublicKeyInfo
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'publicKeyAlgorithm' => AlgorithmIdentifier::MAP,
            'publicKey' => ['type' => ASN1::TYPE_BIT_STRING],
        ],
    ];
}
