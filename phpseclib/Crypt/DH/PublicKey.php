<?php

/**
 * DH Public Key
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\DH;

use phpseclib3\Crypt\Common;
use phpseclib3\Crypt\DH;
use phpseclib3\Math\BigInteger;

/**
 * DH Public Key
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class PublicKey extends DH
{
    use Common\Traits\Fingerprint;

    /**
     * Returns the public key
     *
     * @param array $options optional
     */
    public function toString(string $type, array $options = []): string
    {
        $type = self::validatePlugin('Keys', $type, 'savePublicKey');

        return $type::savePublicKey($this->prime, $this->base, $this->publicKey, $options);
    }

    /**
     * Returns the public key as a BigInteger
     */
    public function toBigInteger(): BigInteger
    {
        return $this->publicKey;
    }
}
