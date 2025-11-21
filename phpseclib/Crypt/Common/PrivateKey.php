<?php

/**
 * PrivateKey interface
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\Common;

use phpseclib4\File\Common\Signable;

/**
 * PrivateKey interface
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
interface PrivateKey
{
    public function sign(string|Signable $message): string;
    //public function decrypt($ciphertext);
    public function getPublicKey(): PublicKey;
    public function toString(string $type, array $options = []): string;

    /**
     * @return static
     */
    public function withPassword(#[SensitiveParameter] ?string $password = null): PrivateKey;
}
