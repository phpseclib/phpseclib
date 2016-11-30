<?php

/**
 * DistributionPointName
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

namespace phpseclib\File\ASN1\Maps;

use phpseclib\File\ASN1;

/**
 * DistributionPointName
 *
 * @package ASN1
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class DistributionPointName
{
    const MAP = [
        'type'     => ASN1::TYPE_CHOICE,
        'children' => [
            'fullName'                => [
                                             'constant' => 0,
                                             'optional' => true,
                                             'implicit' => true
                                   ] + GeneralNames::MAP,
            'nameRelativeToCRLIssuer' => [
                                             'constant' => 1,
                                             'optional' => true,
                                             'implicit' => true
                                   ] + RelativeDistinguishedName::MAP
        ]
    ];
}
