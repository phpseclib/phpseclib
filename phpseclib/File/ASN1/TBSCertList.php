<?php

/**
 * TBSCertList
 *
 * PHP version 5
 *
 * @category  File
 * @package   ASN1
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\File\ASN1;

use phpseclib\File\ASN1;

/**
 * TBSCertList
 *
 * @package ASN1
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class TBSCertList
{
    const MAP = [
        'type'     => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version'             => [
                                         'optional' => true,
                                         'default'  => 'v1'
                                     ] + Version::MAP,
            'signature'           => AlgorithmIdentifier::MAP,
            'issuer'              => Name::MAP,
            'thisUpdate'          => Time::MAP,
            'nextUpdate'          => [
                                         'optional' => true
                                     ] + Time,
            'revokedCertificates' => [
                                         'type'     => ASN1::TYPE_SEQUENCE,
                                         'optional' => true,
                                         'min'      => 0,
                                         'max'      => -1,
                                         'children' => RevokedCertificate::MAP
                                     ],
            'crlExtensions'       => [
                                         'constant' => 0,
                                         'optional' => true,
                                         'explicit' => true
                                     ] + Extensions::MAP
        ]
    ];
}
