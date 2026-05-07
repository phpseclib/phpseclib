<?php

/**
 * EncryptedData
 *
 * This is using the RFC5208 (PKCS#8) definition of EncryptedData:
 * https://datatracker.ietf.org/doc/html/rfc5208#section-6
 *
 * RFC5652 (CMS) has another definition of EncryptedData:
 * https://datatracker.ietf.org/doc/html/rfc5652#section-8
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Maps;

use phpseclib4\File\ASN1;

/**
 * EncryptedData
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class EncryptedData
{
    public const MAP = ['type' => ASN1::TYPE_OCTET_STRING];
}
