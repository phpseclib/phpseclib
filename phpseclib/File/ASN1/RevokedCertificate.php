<?php

/**
 * RevokedCertificate
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
 * RevokedCertificate
 *
 * @package ASN1
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class RevokedCertificate
{
    const MAP = [
        'type'     => ASN1::TYPE_SEQUENCE,
        'children' => [
                          'userCertificate'    => CertificateSerialNumber::MAP,
                          'revocationDate'     => Time::MAP,
                          'crlEntryExtensions' => [
                                                      'optional' => true
                                                  ] + Extensions::MAP
                      ]
    ];
}
