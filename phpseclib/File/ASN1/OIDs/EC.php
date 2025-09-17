<?php

/**
 * ASN.1 EC OIDs
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\File\ASN1\OIDs;

/**
 * EC OIDs
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class EC
{
    public const OIDs = [
        'prime-field' => '1.2.840.10045.1.1',
        'characteristic-two-field' => '1.2.840.10045.1.2',
        'characteristic-two-basis' => '1.2.840.10045.1.2.3',
        // per http://www.secg.org/SEC1-Ver-1.0.pdf#page=84, gnBasis "not used here"
        'gnBasis' => '1.2.840.10045.1.2.3.1', // NULL
        'tpBasis' => '1.2.840.10045.1.2.3.2', // Trinomial
        'ppBasis' => '1.2.840.10045.1.2.3.3',  // Pentanomial
    ];
}