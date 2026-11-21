<?php

/**
 * ML-DSA Private Key
 *
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\MLDSA;

use phpseclib4\Crypt\{Common, MLDSA};
use phpseclib4\Exception\{BadConfigurationException, BadMethodCallException};
use phpseclib4\File\Common\Signable;

/**
 * ML-DSA Private Key
 *
 * @author  Adriel Cavalcante
 */
final class PrivateKey extends MLDSA implements Common\PrivateKey
{
    use Common\Traits\PasswordProtected;

    /**
     * Seed (xi in FIPS 204)
     *
     * The whole key pair is derived from it. Null if the key was loaded from an expanded private key.
     */
    protected ?string $seed = null;

    /**
     * Expanded private key (sk in FIPS 204)
     *
     * Null if the key was loaded from (or created with) a seed.
     */
    protected ?string $expandedKey = null;

    /**
     * Public key (pk in FIPS 204)
     *
     * Derived with OpenSSL on demand when the key file didn't have it.
     */
    protected ?string $publicKey = null;

    /**
     * Create a signature
     *
     * The signature is hedged (FIPS 204, algorithm 2, with fresh randomness) since that's what OpenSSL does;
     * ext/openssl has no option for the deterministic variant. The message is hashed by ML-DSA itself.
     *
     * @see self::verify()
     */
    public function sign(string|Signable $source): string|array
    {
        if ($source instanceof Signable) {
            throw new BadMethodCallException('ML-DSA keys cannot sign X.509 certificates, CSRs or CRLs yet');
        }

        self::assertEngine();
        $this->assertContextSupported();

        $signature = '';
        // algorithm 0 is used because ML-DSA has a built-in hash
        $result = openssl_sign($source, $signature, $this->withPassword()->toString('PKCS8'), 0);
        if (!$result) {
            $error = openssl_error_string();
            self::clearOpenSSLErrors();
            throw new BadConfigurationException('OpenSSL was unable to create the ML-DSA signature' . ($error ? ' because of ' . $error : ''));
        }

        return $signature;
    }

    /**
     * Returns the private key
     *
     * @param array $options optional
     */
    public function toString(string $type, array $options = []): string
    {
        $type = self::validatePlugin('Keys', $type, 'savePrivateKey');

        return $type::savePrivateKey($this->parameterSet, $this->seed, $this->expandedKey, $this->password, $options);
    }

    /**
     * Returns the public key
     */
    public function getPublicKey(): PublicKey
    {
        $type = self::validatePlugin('Keys', 'PKCS8', 'savePublicKey');

        $key = $type::savePublicKey($this->parameterSet, $this->getRawPublicKey());
        $key = MLDSA::loadFormat('PKCS8', $key);

        return $key->withContext($this->context);
    }

    /**
     * Returns the raw public key, deriving it with OpenSSL if need be
     */
    private function getRawPublicKey(): string
    {
        if (!isset($this->publicKey)) {
            $this->publicKey = self::derivePublicKey($this->withPassword()->toString('PKCS8'), $this->parameterSet);
        }

        return $this->publicKey;
    }
}
