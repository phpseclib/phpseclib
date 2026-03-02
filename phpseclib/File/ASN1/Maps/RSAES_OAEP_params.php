<?php

/**
 * RSAES_OAEP_params
 *
 * As defined in https://tools.ietf.org/html/rfc4055#section-3.1
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
 * RSAES_OAEP_params
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class RSAES_OAEP_params
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'hashAlgorithm' => [
                'constant' => 0,
                'optional' => true,
                'explicit' => true,
                //'default'  => 'sha1'
            ] + HashAlgorithm::MAP,
            'maskGenAlgorithm' => [
                'constant' => 1,
                'optional' => true,
                'explicit' => true,
                //'default'  => 'mgf1SHA1'
            ] + MaskGenAlgorithm::MAP,
            'pSourceAlgorithm' => [
                'constant' => 2,
                'optional' => true,
                'explicit' => true,
                //'default' => 'pSpecifiedEmpty,
            ] + PSourceAlgorithm::MAP,
        ],
    ];
}
