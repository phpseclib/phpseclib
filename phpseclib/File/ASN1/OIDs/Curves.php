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
 * the sec* curves are from the standards for efficient cryptography group
 * sect* curves are curves over binary finite fields
 * secp* curves are curves over prime finite fields
 * sec*r* curves are regular curves; sec*k* curves are koblitz curves
 * brainpool*r* curves are regular prime finite field curves
 * brainpool*t* curves are twisted versions of the brainpool*r* curves
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Curves
{
    public const OIDs = [
        'prime192v1' => '1.2.840.10045.3.1.1', // J.5.1, example 1 (aka secp192r1)
        'prime192v2' => '1.2.840.10045.3.1.2', // J.5.1, example 2
        'prime192v3' => '1.2.840.10045.3.1.3', // J.5.1, example 3
        'prime239v1' => '1.2.840.10045.3.1.4', // J.5.2, example 1
        'prime239v2' => '1.2.840.10045.3.1.5', // J.5.2, example 2
        'prime239v3' => '1.2.840.10045.3.1.6', // J.5.2, example 3
        'prime256v1' => '1.2.840.10045.3.1.7', // J.5.3, example 1 (aka secp256r1)

        // https://tools.ietf.org/html/rfc5656#section-10
        'nistp256' => '1.2.840.10045.3.1.7', // aka secp256r1
        'nistp384' => '1.3.132.0.34', // aka secp384r1
        'nistp521' => '1.3.132.0.35', // aka secp521r1

        'nistk163' => '1.3.132.0.1', // aka sect163k1
        'nistp192' => '1.2.840.10045.3.1.1', // aka secp192r1
        'nistp224' => '1.3.132.0.33', // aka secp224r1
        'nistk233' => '1.3.132.0.26', // aka sect233k1
        'nistb233' => '1.3.132.0.27', // aka sect233r1
        'nistk283' => '1.3.132.0.16', // aka sect283k1
        'nistk409' => '1.3.132.0.36', // aka sect409k1
        'nistb409' => '1.3.132.0.37', // aka sect409r1
        'nistt571' => '1.3.132.0.38', // aka sect571k1

        // from https://tools.ietf.org/html/rfc5915
        'secp192r1' => '1.2.840.10045.3.1.1', // aka prime192v1
        'sect163k1' => '1.3.132.0.1',
        'sect163r2' => '1.3.132.0.15',
        'secp224r1' => '1.3.132.0.33',
        'sect233k1' => '1.3.132.0.26',
        'sect233r1' => '1.3.132.0.27',
        'secp256r1' => '1.2.840.10045.3.1.7', // aka prime256v1
        'sect283k1' => '1.3.132.0.16',
        'sect283r1' => '1.3.132.0.17',
        'secp384r1' => '1.3.132.0.34',
        'sect409k1' => '1.3.132.0.36',
        'sect409r1' => '1.3.132.0.37',
        'secp521r1' => '1.3.132.0.35',
        'sect571k1' => '1.3.132.0.38',
        'sect571r1' => '1.3.132.0.39',
        // from http://www.secg.org/SEC2-Ver-1.0.pdf
        'secp112r1' => '1.3.132.0.6',
        'secp112r2' => '1.3.132.0.7',
        'secp128r1' => '1.3.132.0.28',
        'secp128r2' => '1.3.132.0.29',
        'secp160k1' => '1.3.132.0.9',
        'secp160r1' => '1.3.132.0.8',
        'secp160r2' => '1.3.132.0.30',
        'secp192k1' => '1.3.132.0.31',
        'secp224k1' => '1.3.132.0.32',
        'secp256k1' => '1.3.132.0.10',

        'sect113r1' => '1.3.132.0.4',
        'sect113r2' => '1.3.132.0.5',
        'sect131r1' => '1.3.132.0.22',
        'sect131r2' => '1.3.132.0.23',
        'sect163r1' => '1.3.132.0.2',
        'sect193r1' => '1.3.132.0.24',
        'sect193r2' => '1.3.132.0.25',
        'sect239k1' => '1.3.132.0.3',

        // from http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&rep=rep1&type=pdf#page=36
        /*
        'c2pnb163v1' => '1.2.840.10045.3.0.1', // J.4.1, example 1
        'c2pnb163v2' => '1.2.840.10045.3.0.2', // J.4.1, example 2
        'c2pnb163v3' => '1.2.840.10045.3.0.3', // J.4.1, example 3
        'c2pnb172w1' => '1.2.840.10045.3.0.4', // J.4.2, example 1
        'c2tnb191v1' => '1.2.840.10045.3.0.5', // J.4.3, example 1
        'c2tnb191v2' => '1.2.840.10045.3.0.6', // J.4.3, example 2
        'c2tnb191v3' => '1.2.840.10045.3.0.7', // J.4.3, example 3
        'c2onb191v4' => '1.2.840.10045.3.0.8', // J.4.3, example 4
        'c2onb191v5' => '1.2.840.10045.3.0.9', // J.4.3, example 5
        'c2pnb208w1' => '1.2.840.10045.3.0.10', // J.4.4, example 1
        'c2tnb239v1' => '1.2.840.10045.3.0.11', // J.4.5, example 1
        'c2tnb239v2' => '1.2.840.10045.3.0.12', // J.4.5, example 2
        'c2tnb239v3' => '1.2.840.10045.3.0.13', // J.4.5, example 3
        'c2onb239v4' => '1.2.840.10045.3.0.14', // J.4.5, example 4
        'c2onb239v5' => '1.2.840.10045.3.0.15', // J.4.5, example 5
        'c2pnb272w1' => '1.2.840.10045.3.0.16', // J.4.6, example 1
        'c2pnb304w1' => '1.2.840.10045.3.0.17', // J.4.7, example 1
        'c2tnb359v1' => '1.2.840.10045.3.0.18', // J.4.8, example 1
        'c2pnb368w1' => '1.2.840.10045.3.0.19', // J.4.9, example 1
        'c2tnb431r1' => '1.2.840.10045.3.0.20', // J.4.10, example 1
        */

        // http://www.ecc-brainpool.org/download/Domain-parameters.pdf
        // https://tools.ietf.org/html/rfc5639
        'brainpoolP160r1' => '1.3.36.3.3.2.8.1.1.1',
        'brainpoolP160t1' => '1.3.36.3.3.2.8.1.1.2',
        'brainpoolP192r1' => '1.3.36.3.3.2.8.1.1.3',
        'brainpoolP192t1' => '1.3.36.3.3.2.8.1.1.4',
        'brainpoolP224r1' => '1.3.36.3.3.2.8.1.1.5',
        'brainpoolP224t1' => '1.3.36.3.3.2.8.1.1.6',
        'brainpoolP256r1' => '1.3.36.3.3.2.8.1.1.7',
        'brainpoolP256t1' => '1.3.36.3.3.2.8.1.1.8',
        'brainpoolP320r1' => '1.3.36.3.3.2.8.1.1.9',
        'brainpoolP320t1' => '1.3.36.3.3.2.8.1.1.10',
        'brainpoolP384r1' => '1.3.36.3.3.2.8.1.1.11',
        'brainpoolP384t1' => '1.3.36.3.3.2.8.1.1.12',
        'brainpoolP512r1' => '1.3.36.3.3.2.8.1.1.13',
        'brainpoolP512t1' => '1.3.36.3.3.2.8.1.1.14',
    ];
}