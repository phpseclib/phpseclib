<?php

/**
 * SubjectInfoAccessSyntax
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2019-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Maps;

use phpseclib4\File\ASN1;

/**
 * SubjectInfoAccessSyntax
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class SubjectInfoAccessSyntax
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'min' => 1,
        'max' => -1,
        'children' => AccessDescription::MAP,
    ];
}
