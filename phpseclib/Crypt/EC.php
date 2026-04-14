<?php

/**
 * Pure-PHP implementation of EC.
 *
 * PHP version 5
 *
 * Here's an example of how to create signatures and verify signatures with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * $private = \phpseclib4\Crypt\EC::createKey('secp256k1');
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
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt;

use phpseclib4\Crypt\Common\AsymmetricKey;
use phpseclib4\Crypt\EC\BaseCurves\{
    Binary as BinaryCurve,
    Montgomery as MontgomeryCurve,
    TwistedEdwards as TwistedEdwardsCurve
};
use phpseclib4\Crypt\EC\Curves\{Curve25519, Ed25519, Ed448};
use phpseclib4\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib4\Crypt\EC\{Parameters, PrivateKey, PublicKey};
use phpseclib4\Exception\{
    BadConfigurationException,
    BadMethodCallException,
    LengthException,
    UnsupportedCurveException
};
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Maps\ECParameters;
use phpseclib4\Math\BigInteger;

/**
 * Pure-PHP implementation of EC.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class EC extends AsymmetricKey
{
    /**
     * Algorithm Name
     *
     * @var string
     */
    public const ALGORITHM = 'EC';

    /**
     * Public Key QA
     *
     * @var object[]
     */
    protected array $QA;

    /**
     * Curve
     */
    protected $curve;

    /**
     * Signature Format (Short)
     */
    protected string $shortFormat = 'ASN1';

    /**
     * Curve Name
     */
    private string $curveName;

    /**
     * Curve Order
     *
     * Used for deterministic ECDSA
     */
    protected BigInteger $q;

    /**
     * Alias for the private key
     *
     * Used for deterministic ECDSA. AsymmetricKey expects $x. I don't like x because
     * with x you have x * the base point yielding an (x, y)-coordinate that is the
     * public key. But the x is different depending on which side of the equal sign
     * you're on. It's less ambiguous if you do dA * base point = (x, y)-coordinate.
     */
    protected BigInteger $x;

    /**
     * Context
     */
    protected ?string $context = null;

    /**
     * Signature Format
     */
    protected string $sigFormat;

    /**
     * Forced Engine
     *
     * @see parent::forceEngine()
     */
    protected static ?string $forcedEngine = null;

    /**
     * Create public / private key pair.
     */
    public static function createKey(string $curve): PrivateKey
    {
        self::initialize_static_variables();

        $class = new \ReflectionClass(static::class);
        if ($class->isFinal()) {
            throw new BadMethodCallException('createKey() should not be called from final classes (' . static::class . ')');
        }

        $curveName = self::getCurveCase($curve);
        $curve = '\phpseclib4\Crypt\EC\Curves\\' . $curveName;

        if (!class_exists($curve)) {
            throw new UnsupportedCurveException('Named Curve of ' . $curveName . ' is not supported');
        }

        $reflect = new \ReflectionClass($curve);
        $curveName = $reflect->isFinal() ?
            $reflect->getParentClass()->getShortName() :
            $reflect->getShortName();
        $curveEngineName = self::getOpenSSLCurveName(strtolower($curveName));

        $providers = match ($curveName) {
            'Ed25519' => [
                    'libsodium' => function_exists('sodium_crypto_sign_keypair'),
                    // OPENSSL_KEYTYPE_ED25519 introduced in PHP 8.4.0
                    'OpenSSL'   => defined('OPENSSL_KEYTYPE_ED25519'),
                ],
            // OPENSSL_KEYTYPE_ED448 introduced in PHP 8.4.0
            'Ed448' => ['OpenSSL' => defined('OPENSSL_KEYTYPE_ED448')],
            'Curve25519' => [
                'libsodium' => function_exists('sodium_crypto_box_publickey_from_secretkey'),
                // OPENSSL_KEYTYPE_X25519 introduced in PHP 8.4.0
                'OpenSSL'   => defined('OPENSSL_KEYTYPE_X25519'),
            ],
            // OPENSSL_KEYTYPE_X448 introduced in PHP 8.4.0
            'Curve448' => ['OpenSSL' => defined('OPENSSL_KEYTYPE_X448')],
            // openssl_get_curve_names() was introduced in PHP 7.1.0
            // exclude curve25519 and curve448 from testing
            default => ['OpenSSL' => function_exists('openssl_get_curve_names') && substr($curveEngineName, 0, 5) != 'curve' && in_array($curveEngineName, openssl_get_curve_names())]
        };

        foreach ($providers as $engine => $isSupported) {
            // if an engine is being forced and the forced engine doesn't match $engine, skip it
            if (isset(self::$forcedEngine) && self::$forcedEngine !== $engine) {
                continue;
            }
            if ($isSupported) {
                $result = self::generateWithEngine($engine, $curveEngineName);
                if (isset($result)) {
                    return $result;
                }
            }
            if (self::$forcedEngine === $engine) {
                throw new BadConfigurationException("EC::createKey: Engine $engine is forced but unsupported for $curve");
            }
        }

        $privatekey = new PrivateKey();

        $curve = new $curve();
        if ($curve instanceof TwistedEdwardsCurve) {
            $arr = $curve->extractSecret(Random::string($curve instanceof Ed448 ? 57 : 32));
            $privatekey->dA = $dA = $arr['dA'];
            $privatekey->secret = $arr['secret'];
        } else {
            $privatekey->dA = $dA = $curve->createRandomMultiplier();
        }
        $privatekey->curve = $curve;
        $privatekey->curveName = $curveName;
        $privatekey->QA = $curve->multiplyPoint($curve->getBasePoint(), $dA);

        //$publickey = clone $privatekey;
        //unset($publickey->dA);
        //unset($publickey->x);

        //$publickey->curveName = $curveName;

        if ($privatekey->curve instanceof TwistedEdwardsCurve) {
            return $privatekey->withHash($curve::HASH);
        }

        return $privatekey;
    }

    /**
     * Returns the actual case of the curve
     *
     * Useful for initializing the curve class
     */
    private static function getCurveCase(string $curveName): string
    {
        $curveName = strtolower($curveName);
        if (preg_match('#(?:^curve|^ed)\d+$#', $curveName)) {
            return ucfirst($curveName);
        }
        if (substr($curveName, 0, 10) == 'brainpoolp') {
            return 'brainpoolP' . substr($curveName, 10);
        }
        return $curveName;
    }

    /**
     * Return the OpenSSL name for a curve
     */
    private static function getOpenSSLCurveName(string $curve): string
    {
        return match ($curve) {
            'secp256r1' => 'prime256v1',
            'secp192r1' => 'prime192v1',
            default => $curve
        };
    }

    /**
     * Generate the key for a given curve / engine combo
     */
    private static function generateWithEngine(string $engine, string $curve): ?PrivateKey
    {
        if ($engine == 'libsodium') {
            if ($curve == 'ed25519') {
                $kp = sodium_crypto_sign_keypair();

                $privatekey = EC::loadFormat('libsodium', sodium_crypto_sign_secretkey($kp));
                //$publickey = EC::loadFormat('libsodium', sodium_crypto_sign_publickey($kp));

                $privatekey->curveName = 'Ed25519';
                //$publickey->curveName = $curve;

                return $privatekey;
            } else { // $curve == 'curve25519
                $privatekey = new PrivateKey();
                $privatekey->curve = new Curve25519();
                $privatekey->curveName = 'Curve25519';
                $privatekey->dA = $privatekey->curve->createRandomMultiplier();
                $dA = str_pad($privatekey->dA->toBytes(), 32, "\0", STR_PAD_LEFT);
                //$r = pack('H*', '0900000000000000000000000000000000000000000000000000000000000000');
                //$QA = sodium_crypto_scalarmult($dA, $r);
                $QA = sodium_crypto_box_publickey_from_secretkey($dA);
                $privatekey->QA = [$privatekey->curve->convertInteger(new BigInteger(strrev($QA), 256))];
                return $privatekey;
            }
        }

        // at this point $engine == 'OpenSSL'

        $curveName = self::getCurveCase($curve);

        $config = [];
        if (self::$configFile) {
            $config['config'] = self::$configFile;
        }
        $params = $config;
        $params['private_key_type'] = match ($curve) {
            'ed25519' => OPENSSL_KEYTYPE_ED25519,
            'ed448' => OPENSSL_KEYTYPE_ED448,
            'curve25519' => OPENSSL_KEYTYPE_X25519,
            'curve448' => OPENSSL_KEYTYPE_X448,
            default => OPENSSL_KEYTYPE_EC
        };
        if ($params['private_key_type'] == OPENSSL_KEYTYPE_EC) {
            $params['curve_name'] = $curveName;
        }

        $key = openssl_pkey_new($params);
        if (!$key) {
            return null;
        }
        $privateKeyStr = '';
        if (!openssl_pkey_export($key, $privateKeyStr, null, $config)) {
            return null;
        }
        // clear the buffer of error strings
        while (openssl_error_string() !== false) {
        }
        // some versions of OpenSSL / PHP return PKCS1 keys, others return PKCS8 keys
        $privatekey = EC::load($privateKeyStr);
        $privatekey->curveName = match ($curveName) {
            'prime256v1' => 'secp256r1',
            'prime192v1' => 'secp192r1',
            default => $curveName
        };
        return $privatekey;
    }

    /**
     * OnLoad Handler
     */
    protected static function onLoad(array $components): EC
    {
        if (!isset($components['dA']) && !isset($components['QA'])) {
            $new = new Parameters();
            $new->curve = $components['curve'];
            return $new;
        }

        $new = isset($components['dA']) ?
            new PrivateKey() :
            new PublicKey();
        $new->curve = $components['curve'];
        $new->QA = $components['QA'];

        if (isset($components['dA'])) {
            $new->dA = $components['dA'];
            $new->secret = $components['secret'];
        }

        if ($new->curve instanceof TwistedEdwardsCurve) {
            return $new->withHash($components['curve']::HASH);
        }

        return $new;
    }

    /**
     * Constructor
     *
     * PublicKey and PrivateKey objects can only be created from abstract RSA class
     */
    protected function __construct()
    {
        $this->sigFormat = self::validatePlugin('Signature', 'ASN1');

        parent::__construct();
    }

    /**
     * Returns the curve
     *
     * Returns a string if it's a named curve, an array if not
     */
    public function getCurve(): string|array
    {
        if (isset($this->curveName)) {
            return $this->curveName;
        }

        if ($this->curve instanceof MontgomeryCurve) {
            $this->curveName = $this->curve instanceof Curve25519 ? 'Curve25519' : 'Curve448';
            return $this->curveName;
        }

        if ($this->curve instanceof TwistedEdwardsCurve) {
            $this->curveName = $this->curve instanceof Ed25519 ? 'Ed25519' : 'Ed448';
            return $this->curveName;
        }

        $params = $this->getParameters()->toString('PKCS8', ['namedCurve' => true]);
        $decoded = ASN1::extractBER($params);
        $decoded = ASN1::decodeBER($decoded);
        $decoded = ASN1::map($decoded, ECParameters::MAP)->toArray();
        if (isset($decoded['namedCurve'])) {
            $this->curveName = (string) $decoded['namedCurve'];
            return (string) $decoded['namedCurve'];
        }

        return $decoded;
    }

    public function isBinaryCurve(): bool
    {
        return $this->curve instanceof BinaryCurve;
    }

    /**
     * Returns the key size
     *
     * Quoting https://tools.ietf.org/html/rfc5656#section-2,
     *
     * "The size of a set of elliptic curve domain parameters on a prime
     *  curve is defined as the number of bits in the binary representation
     *  of the field order, commonly denoted by p.  Size on a
     *  characteristic-2 curve is defined as the number of bits in the binary
     *  representation of the field, commonly denoted by m.  A set of
     *  elliptic curve domain parameters defines a group of order n generated
     *  by a base point P"
     */
    public function getLength(): int
    {
        return $this->curve->getLength();
    }

    /**
     * Returns the public key coordinates as a string
     *
     * Used by ECDH
     */
    public function getEncodedCoordinates(): string
    {
        if ($this->curve instanceof MontgomeryCurve) {
            return strrev($this->QA[0]->toBytes(true));
        }
        if ($this->curve instanceof TwistedEdwardsCurve) {
            return $this->curve->encodePoint($this->QA);
        }
        return "\4" . $this->QA[0]->toBytes(true) . $this->QA[1]->toBytes(true);
    }

    // for Weierstrass curves, if only the x coordinate is present (as is the case after doing a round of ECDH)
    // then we'll guess at the y coordinate. there are only two possible y values and, atleast in-so-far as
    // multiplication is concerned, neither value affects the resultant x value
    public static function convertPointToPublicKey(string $curveName, string $secret, bool $toPublicKey = true): PublicKey|string
    {
        $curveName = self::getCurveCase($curveName);
        $curve = '\phpseclib4\Crypt\EC\Curves\\' . $curveName;

        if (!class_exists($curve)) {
            throw new UnsupportedCurveException('Named Curve of ' . $curveName . ' is not supported');
        }

        $curve = new $curve();
        if (!$curve instanceof TwistedEdwardsCurve) {
            if ($curve instanceof MontgomeryCurve) {
                $secret = strrev($secret);
            } elseif ($curve->getLengthInBytes() == strlen($secret)) {
                $secret = "\3$secret";
            }
            if (!$toPublicKey) {
                return $secret;
            }
            $secret = "\0$secret";
        } elseif (!$toPublicKey) {
            return $secret;
        }
        $QA = PKCS8::extractPoint($secret, $curve);
        $key = PKCS8::savePublicKey($curve, $QA);
        return EC::loadFormat('PKCS8', $key);
    }

    /**
     * Returns the parameters
     *
     * @see self::getPublicKey()
     */
    public function getParameters(string $type = 'PKCS1'): ?Parameters
    {
        $type = self::validatePlugin('Keys', $type, 'saveParameters');

        $key = $type::saveParameters($this->curve);

        return EC::load($key, 'PKCS1')
            ->withHash($this->hash->getHash())
            ->withSignatureFormat($this->shortFormat);
    }

    /**
     * Determines the signature padding mode
     *
     * Valid values are: ASN1, SSH2, Raw
     */
    public function withSignatureFormat(string $format): EC
    {
        if ($this->curve instanceof MontgomeryCurve) {
            throw new BadMethodCallException('Montgomery Curves cannot be used to create signatures');
        }

        $new = clone $this;
        $new->shortFormat = $format;
        $new->sigFormat = self::validatePlugin('Signature', $format);
        return $new;
    }

    /**
     * Returns the signature format currently being used
     */
    public function getSignatureFormat(): string
    {
        return $this->shortFormat;
    }

    /**
     * Sets the context
     *
     * Used by Ed25519 / Ed448.
     *
     * @see self::verify()
     * @see self::sign()
     */
    public function withContext(?string $context = null): EC
    {
        if (!$this->curve instanceof TwistedEdwardsCurve) {
            throw new BadMethodCallException('Only Ed25519 and Ed448 support contexts');
        }

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
     * Returns the signature format currently being used
     */
    public function getContext(): string
    {
        return $this->context;
    }

    /**
     * Determines which hashing function should be used
     */
    public function withHash(string $hash): AsymmetricKey
    {
        if ($this->curve instanceof MontgomeryCurve) {
            throw new BadMethodCallException('Montgomery Curves cannot be used to create signatures');
        }
        if ($this->curve instanceof Ed25519 && $hash != 'sha512') {
            throw new BadMethodCallException('Ed25519 only supports sha512 as a hash');
        }
        if ($this->curve instanceof Ed448 && $hash != 'shake256-912') {
            throw new BadMethodCallException('Ed448 only supports shake256 with a length of 114 bytes');
        }

        return parent::withHash($hash);
    }
}
