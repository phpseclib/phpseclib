<?php

/**
 * ASN.1 Octet String
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2012 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\File\ASN1\Types;

/**
 * ASN.1 Octet String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class OctetString extends BaseString
{
    public const TYPE = 4;

    public function __debugInfo(): array
    {
        return ['value' => bin2hex($this->value)];
    }
}
