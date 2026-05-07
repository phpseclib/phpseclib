<?php

/**
 * ASN.1 UTC Time
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Types;

/**
 * ASN.1 UTC Time
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class UTCTime extends \DateTime implements BaseType
{
    use Common;

    public const TYPE = 23;

    public function __toString(): string
    {
        return $this->format('Y-m-d H:i:s');
    }
}
