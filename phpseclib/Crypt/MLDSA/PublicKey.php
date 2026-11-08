<?php

/**
 * ML-DSA Public Key
 *
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\MLDSA;

use phpseclib4\Crypt\{Common, MLDSA};
use phpseclib4\Exception\UnexpectedValueException;

/**
 * ML-DSA Public Key
 *
 * @author  Adriel Cavalcante
 */
final class PublicKey extends MLDSA implements Common\PublicKey
{
    use Common\Traits\Fingerprint;

    /**
     * Public key (pk in FIPS 204)
     */
    protected string $publicKey;

    /**
     * Verify a signature
     *
     * @see self::sign()
     */
    public function verify(string $message, string|array $signature): bool
    {
        if (is_array($signature)) {
            throw new UnexpectedValueException('ML-DSA signatures are strings, not arrays');
        }

        self::assertEngine();
        $this->assertContextSupported();

        if (strlen($signature) != self::PARAMETER_SETS[$this->parameterSet]['signature']) {
            return false;
        }

        // algorithm 0 is used because ML-DSA has a built-in hash
        $result = openssl_verify($message, $signature, $this->toString('PKCS8'), 0);
        self::clearOpenSSLErrors();

        return $result === 1;
    }

    /**
     * Returns the public key
     */
    public function toString(string $type, array $options = []): string
    {
        $type = self::validatePlugin('Keys', $type, 'savePublicKey');

        return $type::savePublicKey($this->parameterSet, $this->publicKey, $options);
    }
}
