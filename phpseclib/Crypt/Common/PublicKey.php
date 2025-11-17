<?php

/**
 * PublicKey interface
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\Common;

/**
 * PublicKey interface
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
interface PublicKey
{
    public function verify(string $message, string $signature): bool;
    //public function encrypt(string $plaintext): string;
    public function toString(string $type, array $options = []): string;
    public function getFingerprint(string $algorithm): string;
}
