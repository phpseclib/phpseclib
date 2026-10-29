<?php

/**
 * ML-DSA (FIPS 204) with an OpenSSL engine
 *
 * PHP version 8.1+
 *
 * Here's an example of how to create signatures and verify signatures with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * $private = \phpseclib4\Crypt\MLDSA::createKey('ML-DSA-65');
 * $public = $private->getPublicKey();
 *
 * $plaintext = 'terrafrost';
 *
 * $signature = $private->sign($plaintext);
 *
 * echo $public->verify($plaintext, $signature) ? 'verified' : 'unverified';
 * ?>
 * </code>
 *
 * There is no pure-PHP engine yet. Key generation, signing and verification go through
 * ext/openssl, which has to be built against OpenSSL 3.5+ (PHP 8.4+). Loading and saving
 * keys (PKCS#8 as described in RFC 9881) works on every supported PHP version.
 *
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\Crypt;

use phpseclib4\Crypt\Common\AsymmetricKey;
use phpseclib4\Crypt\MLDSA\Formats\Keys\PKCS8;
use phpseclib4\Crypt\MLDSA\{PrivateKey, PublicKey};
use phpseclib4\Exception\{
    BadConfigurationException,
    BadMethodCallException,
    LengthException,
    UnexpectedValueException,
    UnsupportedAlgorithmException
};

/**
 * ML-DSA (FIPS 204) with an OpenSSL engine
 *
 * @author  Adriel Cavalcante
 */
abstract class MLDSA extends AsymmetricKey
{
    /**
     * Algorithm Name
     *
     * @var string
     */
    public const ALGORITHM = 'MLDSA';

    /**
     * Length of the seed (xi in FIPS 204) in bytes
     */
    public const SEED_LENGTH = 32;

    /**
     * Sizes, in bytes, of the public key, the expanded private key and the signature
     *
     * See FIPS 204, table 2
     */
    public const PARAMETER_SETS = [
        'ML-DSA-44' => ['publicKey' => 1312, 'expandedKey' => 2560, 'signature' => 2420],
        'ML-DSA-65' => ['publicKey' => 1952, 'expandedKey' => 4032, 'signature' => 3309],
        'ML-DSA-87' => ['publicKey' => 2592, 'expandedKey' => 4896, 'signature' => 4627],
    ];

    /**
     * ML-DSA-44 private key derived from an all-zero seed (seed-only PKCS#8 of RFC 9881)
     *
     * Used to check, once, that ext/openssl can actually handle ML-DSA keys
     */
    private const PROBE_KEY = "-----BEGIN PRIVATE KEY-----\r\n" .
        "MDQCAQAwCwYJYIZIAWUDBAMRBCKAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" .
        "-----END PRIVATE KEY-----";

    /**
     * SHA-256 of the public key that corresponds to self::PROBE_KEY
     */
    private const PROBE_PUBLIC_KEY_HASH = 'eb4e7302842153b0fa19e8620739ad258af4929c26dd89079a7ec7d4282208e1';

    /**
     * Parameter Set
     *
     * One of ML-DSA-44, ML-DSA-65 or ML-DSA-87
     */
    protected string $parameterSet;

    /**
     * Context
     */
    protected ?string $context = null;

    /**
     * Forced Engine
     *
     * @see parent::forceEngine()
     */
    protected static ?string $forcedEngine = null;

    /**
     * Whether or not ext/openssl can handle ML-DSA keys
     *
     * @see self::isSupported()
     */
    private static ?bool $engineAvailable = null;

    /**
     * Create a private key
     *
     * Draws a random 32-byte seed and loads it as a seed-only PrivateKeyInfo (RFC 9881); OpenSSL
     * expands it into the key pair, which is how FIPS 204 defines key generation (ML-DSA.KeyGen,
     * algorithm 1, draws the seed and ML-DSA.KeyGen_internal derives everything else from it).
     * The key object keeps the seed, so the key is saved in that same form.
     */
    public static function createKey(string $parameterSet): PrivateKey
    {
        self::initialize_static_variables();

        $class = new \ReflectionClass(static::class);
        if ($class->isFinal()) {
            throw new BadMethodCallException('createKey() should not be called from final classes (' . static::class . ')');
        }

        $parameterSet = self::getParameterSetName($parameterSet);

        self::assertEngine();

        $privatekey = new PrivateKey();
        $privatekey->parameterSet = $parameterSet;
        $privatekey->seed = random_bytes(self::SEED_LENGTH);
        // derive the public key now so that a broken OpenSSL setup fails here and not at the first sign()
        $privatekey->publicKey = self::derivePublicKey($privatekey->toString('PKCS8'), $parameterSet);

        return $privatekey;
    }

    /**
     * Returns the canonical name of a parameter set
     *
     * ML-DSA-44, ml-dsa-44, MLDSA44 and mldsa44 all mean the same thing
     */
    public static function getParameterSetName(string $parameterSet): string
    {
        if (!preg_match('#^ml-?dsa-?(44|65|87)$#i', $parameterSet, $matches)) {
            throw new UnsupportedAlgorithmException("$parameterSet is not a supported ML-DSA parameter set");
        }
        return 'ML-DSA-' . $matches[1];
    }

    /**
     * OnLoad Handler
     */
    protected static function onLoad(array $components): static
    {
        if (isset($components['seed']) || isset($components['expandedKey'])) {
            $new = new PrivateKey();
            $new->seed = $components['seed'] ?? null;
            $new->expandedKey = $components['expandedKey'] ?? null;
            $new->publicKey = $components['publicKey'] ?? null;
        } else {
            $new = new PublicKey();
            $new->publicKey = $components['publicKey'];
        }

        $new->parameterSet = $components['parameterSet'];

        return $new;
    }

    /**
     * Constructor
     *
     * PublicKey and PrivateKey objects can only be created from the abstract MLDSA class
     */
    protected function __construct()
    {
        parent::__construct();
    }

    /**
     * Is there an engine that can do ML-DSA?
     *
     * The only engine, for now, is OpenSSL 3.5+ through ext/openssl (PHP 8.4+). The first call loads a
     * known key and checks the public key OpenSSL derives from it; the result is cached.
     */
    public static function isSupported(): bool
    {
        if (!isset(self::$engineAvailable)) {
            self::$engineAvailable = self::probeOpenSSL();
        }

        return self::$engineAvailable;
    }

    /**
     * Checks that ext/openssl can load an ML-DSA key and derive the right public key from it
     *
     * PHP 8.4 is required as well: openssl_sign() and openssl_verify() only accept a key
     * without a digest (the Ed25519 / ML-DSA case) since PHP 8.4. Older PHP builds linked
     * against OpenSSL 3.5 can load the key but fail with "Unknown digest algorithm" when signing.
     */
    private static function probeOpenSSL(): bool
    {
        if (PHP_VERSION_ID < 80400 || !function_exists('openssl_pkey_get_private') || OPENSSL_VERSION_NUMBER < 0x30500000) {
            return false;
        }

        $key = openssl_pkey_get_private(self::PROBE_KEY);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        self::clearOpenSSLErrors();
        if ($details === false || !isset($details['key']) || !is_string($details['key'])) {
            return false;
        }

        try {
            $components = PKCS8::load($details['key']);
        } catch (\Throwable) {
            return false;
        }

        return hash('sha256', $components['publicKey']) === self::PROBE_PUBLIC_KEY_HASH;
    }

    /**
     * Throws an exception if the engine can't be used
     */
    protected static function assertEngine(): void
    {
        if (isset(self::$forcedEngine) && self::$forcedEngine !== 'OpenSSL') {
            throw new BadConfigurationException('Engine ' . self::$forcedEngine . ' is forced but unsupported for ML-DSA (OpenSSL is the only ML-DSA engine)');
        }
        if (!self::isSupported()) {
            throw new BadConfigurationException('ML-DSA needs PHP 8.4+ with the OpenSSL extension built against OpenSSL 3.5+ (there is no pure-PHP ML-DSA engine yet)');
        }
    }

    /**
     * Throws an exception if a context has been set
     *
     * FIPS 204 lets a context string (up to 255 bytes) be bound to the signature. openssl_sign() and
     * openssl_verify() have no parameter for it so, with the OpenSSL engine, only the empty context works.
     */
    protected function assertContextSupported(): void
    {
        if (isset($this->context) && $this->context !== '') {
            throw new BadConfigurationException('The OpenSSL engine does not support ML-DSA context strings (ext/openssl has no way to pass one)');
        }
    }

    /**
     * Clear the buffer of OpenSSL error strings
     */
    protected static function clearOpenSSLErrors(): void
    {
        while (openssl_error_string() !== false) {
        }
    }

    /**
     * Derives the public key from a PKCS#8 private key with OpenSSL
     *
     * Returns the raw public key (pk in FIPS 204)
     */
    protected static function derivePublicKey(string $privateKey, string $parameterSet): string
    {
        self::assertEngine();

        $key = openssl_pkey_get_private($privateKey);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($details === false || !isset($details['key']) || !is_string($details['key'])) {
            $error = openssl_error_string();
            self::clearOpenSSLErrors();
            throw new BadConfigurationException('OpenSSL was unable to load the ML-DSA private key' . ($error ? ' because of ' . $error : ''));
        }

        $components = PKCS8::load($details['key']);
        if ($components['parameterSet'] !== $parameterSet) {
            throw new UnexpectedValueException('OpenSSL returned a ' . $components['parameterSet'] . ' public key for a ' . $parameterSet . ' private key');
        }

        return $components['publicKey'];
    }

    /**
     * Returns the parameter set (ML-DSA-44, ML-DSA-65 or ML-DSA-87)
     */
    public function getParameterSet(): string
    {
        return $this->parameterSet;
    }

    /**
     * Returns the key size
     *
     * ML-DSA has neither a modulus nor a curve, so this is the length of the public key in bits
     * (which is also what openssl_pkey_get_details() reports as "bits")
     */
    public function getLength(): int
    {
        return self::PARAMETER_SETS[$this->parameterSet]['publicKey'] << 3;
    }

    /**
     * Sets the context
     *
     * @see self::verify()
     * @see self::sign()
     */
    public function withContext(?string $context = null): static
    {
        $new = clone $this;
        if (!isset($context)) {
            $new->context = null;
            return $new;
        }

        if (strlen($context) > 255) {
            throw new LengthException('The context is supposed to be, at most, 255 bytes long');
        }
        $new->context = $context;
        return $new;
    }

    /**
     * Returns the context
     */
    public function getContext(): string
    {
        if (!isset($this->context)) {
            throw new BadMethodCallException('No context has been set');
        }
        return $this->context;
    }

    /**
     * Determines which hashing function should be used
     *
     * ML-DSA hashes the message itself (FIPS 204, section 5.2) so there's nothing to configure.
     * HashML-DSA (pre-hashed messages) is not supported.
     */
    public function withHash(string $hash): static
    {
        throw new BadMethodCallException('ML-DSA does not have a configurable hash (' . $hash . ' was requested)');
    }
}
