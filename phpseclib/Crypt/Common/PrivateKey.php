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

namespace phpseclib3\Crypt\Common;

/**
 * PrivateKey interface
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
interface PrivateKey
{
    public function sign($message);
    //public function decrypt($ciphertext);
    public function getPublicKey();
    public function toString(string $type, array $options = []): string;

    /**
     * @return static
     */
    public function withPassword(?string $password = null): PrivateKey;
}
