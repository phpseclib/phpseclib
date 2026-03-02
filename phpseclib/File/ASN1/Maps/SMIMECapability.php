<?php

/**
 * SMIMECapability
 *
 * This is an exact copy of AlgorithmIdentifier, however, https://datatracker.ietf.org/doc/html/rfc2985#section-5.6
 * opts not to use AlgorithmIdentifier as the name so we shant, either
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Maps;

use phpseclib4\File\ASN1;

/**
 * SMIMECapability
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class SMIMECapability extends AlgorithmIdentifier
{
}