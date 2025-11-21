<?php

/**
 * Signable interface
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\Common;

use phpseclib4\Crypt\Common\PrivateKey;

/**
 * Signable interface
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
interface Signable
{
    public function getSignableSection(): string;
    public function setSignature(string $signature): void;
    public static function identifySignatureAlgorithm(PrivateKey $key): array;
    public function setSignatureAlgorithm(array $algorithm): void;
}
