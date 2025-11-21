<?php

/**
 * ASN.1 UTC Time
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2012 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
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
