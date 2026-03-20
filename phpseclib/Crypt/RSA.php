<?php

/**
 * Pure-PHP PKCS#1 (v2.1) compliant implementation of RSA.
 *
 * PHP version 5
 *
 * Here's an example of how to encrypt and decrypt text with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * $private = \phpseclib4\Crypt\RSA::createKey();
 * $public = $private->getPublicKey();
 *
 * $plaintext = 'terrafrost';
 *
 * $ciphertext = $public->encrypt($plaintext);
 *
 * echo $private->decrypt($ciphertext);
 * ?>
 * </code>
 *
 * Here's an example of how to create signatures and verify signatures with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * $private = \phpseclib4\Crypt\RSA::createKey();
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
 * One thing to consider when using this: so phpseclib uses PSS mode by default.
 * Technically, id-RSASSA-PSS has a different key format than rsaEncryption. So
 * should phpseclib save to the id-RSASSA-PSS format by default or the
 * rsaEncryption format? For stand-alone keys I figure rsaEncryption is better
 * because SSH doesn't use PSS and idk how many SSH servers would be able to
 * decode an id-RSASSA-PSS key. For X.509 certificates the id-RSASSA-PSS
 * format is used by default (unless you change it up to use PKCS1 instead)
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt;

use phpseclib4\Crypt\Common\AsymmetricKey;
use phpseclib4\Crypt\RSA\Formats\Keys\PSS;
use phpseclib4\Crypt\RSA\PrivateKey;
use phpseclib4\Crypt\RSA\PublicKey;
use phpseclib4\Exception\BadConfigurationException;
use phpseclib4\Exception\InconsistentSetupException;
use phpseclib4\Exception\LengthException;
use phpseclib4\Exception\OutOfRangeException;
use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\Math\BigInteger;

/**
 * Pure-PHP PKCS#1 compliant implementation of RSA.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class RSA extends AsymmetricKey
{
    /**
     * Algorithm Name
     *
     * @var string
     */
    public const ALGORITHM = 'RSA';

    /**
     * Use {@link http://en.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding Optimal Asymmetric Encryption Padding}
     * (OAEP) for encryption / decryption.
     *
     * Uses sha256 by default
     *
     * @see self::setHash()
     * @see self::setMGFHash()
     * @see self::encrypt()
     * @see self::decrypt()
     */
    public const ENCRYPTION_OAEP = 1;

    /**
     * Use PKCS#1 padding.
     *
     * Although self::PADDING_OAEP / self::PADDING_PSS  offers more security, including PKCS#1 padding is necessary for purposes of backwards
     * compatibility with protocols (like SSH-1) written before OAEP's introduction.
     *
     * @see self::encrypt()
     * @see self::decrypt()
     */
    public const ENCRYPTION_PKCS1 = 2;

    /**
     * Do not use any padding
     *
     * Although this method is not recommended it can none-the-less sometimes be useful if you're trying to decrypt some legacy
     * stuff, if you're trying to diagnose why an encrypted message isn't decrypting, etc.
     *
     * @see self::encrypt()
     * @see self::decrypt()
     */
    public const ENCRYPTION_NONE = 4;

    /**
     * Use the Probabilistic Signature Scheme for signing
     *
     * Uses sha256 and 0 as the salt length
     *
     * @see self::setSaltLength()
     * @see self::setMGFHash()
     * @see self::setHash()
     * @see self::sign()
     * @see self::verify()
     * @see self::setHash()
     */
    public const SIGNATURE_PSS = 16;

    /**
     * Use a relaxed version of PKCS#1 padding for signature verification
     *
     * @see self::sign()
     * @see self::verify()
     * @see self::setHash()
     */
    public const SIGNATURE_RELAXED_PKCS1 = 32;

    /**
     * Use PKCS#1 padding for signature verification
     *
     * @see self::sign()
     * @see self::verify()
     * @see self::setHash()
     */
    public const SIGNATURE_PKCS1 = 64;

    /**
     * Encryption padding mode
     */
    protected int $encryptionPadding = self::ENCRYPTION_OAEP;

    /**
     * Signature padding mode
     */
    protected int $signaturePadding = self::SIGNATURE_PSS;

    /**
     * Length of hash function output
     */
    protected int $hLen;

    /**
     * Length of salt
     */
    protected ?int $sLen = null;

    /**
     * Label
     */
    protected string $label = '';

    /**
     * Hash function for the Mask Generation Function
     */
    protected Hash $mgfHash;

    /**
     * Length of MGF hash function output
     */
    protected int $mgfHLen;

    /**
     * Modulus (ie. n)
     */
    protected BigInteger $modulus;

    /**
     * Modulus length
     */
    protected int $k;

    /**
     * Exponent (ie. e or d)
     */
    protected BigInteger $exponent;

    /**
     * Default public exponent
     *
     * @link http://en.wikipedia.org/wiki/65537_%28number%29
     */
    private static int $defaultExponent = 65537;

    /**
     * Enable Blinding?
     */
    protected static bool $enableBlinding = true;

    /**
     * Smallest Prime
     *
     * Per <http://cseweb.ucsd.edu/~hovav/dist/survey.pdf#page=5>, this number ought not result in primes smaller
     * than 256 bits. As a consequence if the key you're trying to create is 1024 bits and you've set smallestPrime
     * to 384 bits then you're going to get a 384 bit prime and a 640 bit prime (384 + 1024 % 384). At least if
     * engine is set to self::ENGINE_INTERNAL. If Engine is set to self::ENGINE_OPENSSL then smallest Prime is
     * ignored (ie. multi-prime RSA support is more intended as a way to speed up RSA key generation when there's
     * a chance neither gmp nor OpenSSL are installed)
     */
    private static int $smallestPrime = 4096;

    /**
     * Public Exponent
     */
    protected BigInteger $publicExponent;

    /**
     * Sets the public exponent for key generation
     *
     * This will be 65537 unless changed.
     */
    public static function setExponent(int $val): void
    {
        self::$defaultExponent = $val;
    }

    /**
     * Sets the smallest prime number in bits. Used for key generation
     *
     * This will be 4096 unless changed.
     */
    public static function setSmallestPrime(int $val): void
    {
        self::$smallestPrime = $val;
    }

    /**
     * Create a private key
     *
     * The public key can be extracted from the private key
     */
    public static function createKey(int $bits = 2048): PrivateKey
    {
        self::initialize_static_variables();

        $class = new \ReflectionClass(static::class);
        if ($class->isFinal()) {
            throw new \RuntimeException('createKey() should not be called from final classes (' . static::class . ')');
        }

        if (self::$forcedEngine == 'libsodium' || (self::$forcedEngine == 'OpenSSL' && !function_exists('openssl_pkey_new'))) {
            throw new BadConfigurationException('Engine ' . self::$forcedEngine . ' is forced but unsupported for RSA');
        }

        $regSize = $bits >> 1; // divide by two to see how many bits P and Q would be
        if ($regSize > self::$smallestPrime) {
            $num_primes = floor($bits / self::$smallestPrime);
            $regSize = self::$smallestPrime;
        } else {
            $num_primes = 2;
        }

        if ($num_primes == 2 && $bits >= 384 && self::$defaultExponent == 65537) {
            // at this point the only two supported values for self::$forcedEngine are OpenSSL, PHP and null
            // if it's either OpenSSL or null we'll use OpenSSL (if it's available)
            if (self::$forcedEngine !== 'PHP' && function_exists('openssl_pkey_new')) {
                $config = [];
                if (self::$configFile) {
                    $config['config'] = self::$configFile;
                }
                // OpenSSL uses 65537 as the exponent and requires RSA keys be 384 bits minimum
                $rsa = openssl_pkey_new(['private_key_bits' => $bits] + $config);
                if (!$rsa || !openssl_pkey_export($rsa, $privatekeystr, null, $config)) {
                    if (isset(self::$forcedEngine)) {
                        throw new BadConfigurationException('Engine OpenSSL is forced but produced an error - ' . openssl_error_string());
                    }
                } else {
                    // clear the buffer of error strings stemming from a minimalistic openssl.cnf
                    // https://github.com/php/php-src/issues/11054 talks about other errors this'll pick up
                    while (openssl_error_string() !== false) {
                    }

                    return RSA::load($privatekeystr);
                }
            }
        }

        static $e;
        if (!isset($e)) {
            $e = new BigInteger(self::$defaultExponent);
        }

        $n = clone self::$one;
        $exponents = $coefficients = $primes = [];
        $lcm = [
            'top' => clone self::$one,
            'bottom' => false,
        ];

        do {
            for ($i = 1; $i <= $num_primes; $i++) {
                if ($i != $num_primes) {
                    $primes[$i] = BigInteger::randomPrime($regSize);
                } else {
                    ['min' => $min, 'max' => $max] = BigInteger::minMaxBits($bits);
                    [$min] = $min->divide($n);
                    $min = $min->add(self::$one);
                    [$max] = $max->divide($n);
                    $primes[$i] = BigInteger::randomRangePrime($min, $max);
                }

                // the first coefficient is calculated differently from the rest
                // ie. instead of being $primes[1]->modInverse($primes[2]), it's $primes[2]->modInverse($primes[1])
                if ($i > 2) {
                    $coefficients[$i] = $n->modInverse($primes[$i]);
                }

                $n = $n->multiply($primes[$i]);

                $temp = $primes[$i]->subtract(self::$one);

                // textbook RSA implementations use Euler's totient function instead of the least common multiple.
                // see http://en.wikipedia.org/wiki/Euler%27s_totient_function
                $lcm['top'] = $lcm['top']->multiply($temp);
                $lcm['bottom'] = $lcm['bottom'] === false ? $temp : $lcm['bottom']->gcd($temp);
            }

            [$temp] = $lcm['top']->divide($lcm['bottom']);
            $gcd = $temp->gcd($e);
            $i0 = 1;
        } while (!$gcd->equals(self::$one));

        $coefficients[2] = $primes[2]->modInverse($primes[1]);

        $d = $e->modInverse($temp);

        foreach ($primes as $i => $prime) {
            $temp = $prime->subtract(self::$one);
            $exponents[$i] = $e->modInverse($temp);
        }

        // from <http://tools.ietf.org/html/rfc3447#appendix-A.1.2>:
        // RSAPrivateKey ::= SEQUENCE {
        //     version           Version,
        //     modulus           INTEGER,  -- n
        //     publicExponent    INTEGER,  -- e
        //     privateExponent   INTEGER,  -- d
        //     prime1            INTEGER,  -- p
        //     prime2            INTEGER,  -- q
        //     exponent1         INTEGER,  -- d mod (p-1)
        //     exponent2         INTEGER,  -- d mod (q-1)
        //     coefficient       INTEGER,  -- (inverse of q) mod p
        //     otherPrimeInfos   OtherPrimeInfos OPTIONAL
        // }
        $privatekey = new PrivateKey();
        $privatekey->modulus = $n;
        $privatekey->k = $bits >> 3;
        $privatekey->publicExponent = $e;
        $privatekey->exponent = $d;
        $privatekey->primes = $primes;
        $privatekey->exponents = $exponents;
        $privatekey->coefficients = $coefficients;

        /*
        $publickey = new PublicKey;
        $publickey->modulus = $n;
        $publickey->k = $bits >> 3;
        $publickey->exponent = $e;
        $publickey->publicExponent = $e;
        $publickey->isPublic = true;
        */

        return $privatekey;
    }

    /**
     * OnLoad Handler
     */
    protected static function onLoad(array $components): RSA
    {
        $key = $components['isPublicKey'] ?
            new PublicKey() :
            new PrivateKey();

        $key->modulus = $components['modulus'];
        $key->publicExponent = $components['publicExponent'];
        $key->k = $key->modulus->getLengthInBytes();

        if ($components['isPublicKey'] || !isset($components['privateExponent'])) {
            $key->exponent = $key->publicExponent;
        } else {
            $key->privateExponent = $components['privateExponent'];
            $key->exponent = $key->privateExponent;
            $key->primes = $components['primes'];
            $key->exponents = $components['exponents'];
            $key->coefficients = $components['coefficients'];
        }

        if ($components['format'] == PSS::class) {
            // in the X509 world RSA keys are assumed to use PKCS1 padding by default. only if the key is
            // explicitly a PSS key is the use of PSS assumed. phpseclib does not work like this. phpseclib
            // uses PSS padding by default. it assumes the more secure method by default and altho it provides
            // for the less secure PKCS1 method you have to go out of your way to use it. this is consistent
            // with the latest trends in crypto. libsodium (NaCl) is actually a little more extreme in that
            // not only does it defaults to the most secure methods - it doesn't even let you choose less
            // secure methods
            //$key = $key->withPadding(self::SIGNATURE_PSS);
            if (isset($components['hash'])) {
                $key = $key->withHash($components['hash']);
            }
            if (isset($components['MGFHash'])) {
                $key = $key->withMGFHash($components['MGFHash']);
            }
            if (isset($components['saltLength'])) {
                $key = $key->withSaltLength($components['saltLength']);
            }
        }

        return $key;
    }

    /**
     * Constructor
     *
     * PublicKey and PrivateKey objects can only be created from abstract RSA class
     */
    protected function __construct()
    {
        parent::__construct();

        $this->hLen = $this->hash->getLengthInBytes();
        $this->mgfHash = new Hash('sha256');
        $this->mgfHLen = $this->mgfHash->getLengthInBytes();
    }

    /**
     * Integer-to-Octet-String primitive
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-4.1 RFC3447#section-4.1}.
     */
    protected function i2osp(BigInteger $x, int $xLen): string
    {
        $x = $x->toBytes();
        if (strlen($x) > $xLen) {
            throw new OutOfRangeException('Resultant string length out of range');
        }
        return str_pad($x, $xLen, chr(0), STR_PAD_LEFT);
    }

    /**
     * Octet-String-to-Integer primitive
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-4.2 RFC3447#section-4.2}.
     */
    protected function os2ip(string $x): BigInteger
    {
        return new BigInteger($x, 256);
    }

    /**
     * EMSA-PKCS1-V1_5-ENCODE
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.2 RFC3447#section-9.2}.
     *
     * @throws LengthException if the intended encoded message length is too short
     */
    protected function emsa_pkcs1_v1_5_encode(string $m, int $emLen): string
    {
        $h = $this->hash->hash($m);

        // see http://tools.ietf.org/html/rfc3447#page-43
        $t = match ($this->hash->getHash()) {
            'md2' => "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10",
            'md5' => "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
            'sha1' => "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
            'sha256' => "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
            'sha384' => "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
            'sha512' => "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
            // from https://www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf#page=40
            'sha224' => "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c",
            'sha512/224' => "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05\x05\x00\x04\x1c",
            'sha512/256' => "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06\x05\x00\x04\x20"
        };
        $t .= $h;
        $tLen = strlen($t);

        if ($emLen < $tLen + 11) {
            throw new LengthException('Intended encoded message length too short');
        }

        $ps = str_repeat(chr(0xFF), $emLen - $tLen - 3);

        $em = "\0\1$ps\0$t";

        return $em;
    }

    /**
     * EMSA-PKCS1-V1_5-ENCODE (without NULL)
     *
     * Quoting https://tools.ietf.org/html/rfc8017#page-65,
     *
     * "The parameters field associated with id-sha1, id-sha224, id-sha256,
     *  id-sha384, id-sha512, id-sha512/224, and id-sha512/256 should
     *  generally be omitted, but if present, it shall have a value of type
     *  NULL"
     */
    protected function emsa_pkcs1_v1_5_encode_without_null(string $m, int $emLen): string
    {
        $h = $this->hash->hash($m);

        $hashName = $this->hash->getHash();
        if ($hashName === 'md2' || $hashName === 'md5') {
            throw new UnsupportedAlgorithmException('md2 and md5 require NULLs');
        }

        // see http://tools.ietf.org/html/rfc3447#page-43
        $t = match ($hashName) {
            'sha1' => "\x30\x1f\x30\x07\x06\x05\x2b\x0e\x03\x02\x1a\x04\x14",
            'sha256' => "\x30\x2f\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x04\x20",
            'sha384' => "\x30\x3f\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x04\x30",
            'sha512' => "\x30\x4f\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x04\x40",
            // from https://www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf#page=40
            'sha224' => "\x30\x2b\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x04\x1c",
            'sha512/224' => "\x30\x2b\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05\x04\x1c",
            'sha512/256' => "\x30\x2f\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06\x04\x20"
        };
        $t .= $h;
        $tLen = strlen($t);

        if ($emLen < $tLen + 11) {
            throw new LengthException('Intended encoded message length too short');
        }

        $ps = str_repeat(chr(0xFF), $emLen - $tLen - 3);

        $em = "\0\1$ps\0$t";

        return $em;
    }

    /**
     * MGF1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#appendix-B.2.1 RFC3447#appendix-B.2.1}.
     */
    protected function mgf1(string $mgfSeed, int $maskLen): string
    {
        // if $maskLen would yield strings larger than 4GB, PKCS#1 suggests a "Mask too long" error be output.

        $t = '';
        $count = ceil($maskLen / $this->mgfHLen);
        for ($i = 0; $i < $count; $i++) {
            $c = pack('N', $i);
            $t .= $this->mgfHash->hash($mgfSeed . $c);
        }

        return substr($t, 0, $maskLen);
    }

    /**
     * Returns the key size
     *
     * More specifically, this returns the size of the modulo in bits.
     */
    public function getLength(): int
    {
        return !isset($this->modulus) ? 0 : $this->modulus->getLength();
    }

    /**
     * Determines which hashing function should be used
     *
     * Used with signature production / verification and (if the encryption mode is self::PADDING_OAEP) encryption and
     * decryption.
     */
    public function withHash(string $hash): RSA
    {
        $new = clone $this;

        // \phpseclib4\Crypt\Hash supports algorithms that PKCS#1 doesn't support.  md5-96 and sha1-96, for example.
        switch (strtolower($hash)) {
            case 'md2':
            case 'md5':
            case 'sha1':
            case 'sha256':
            case 'sha384':
            case 'sha512':
            case 'sha224':
            case 'sha512/224':
            case 'sha512/256':
                $new->hash = new Hash($hash);
                break;
            default:
                throw new UnsupportedAlgorithmException(
                    'The only supported hash algorithms are: md2, md5, sha1, sha256, sha384, sha512, sha224, sha512/224, sha512/256'
                );
        }
        $new->hLen = $new->hash->getLengthInBytes();

        return $new;
    }

    /**
     * Determines which hashing function should be used for the mask generation function
     *
     * The mask generation function is used by self::PADDING_OAEP and self::PADDING_PSS and although it's
     * best if Hash and MGFHash are set to the same thing this is not a requirement.
     */
    public function withMGFHash(string $hash): RSA
    {
        $new = clone $this;

        // \phpseclib4\Crypt\Hash supports algorithms that PKCS#1 doesn't support.  md5-96 and sha1-96, for example.
        switch (strtolower($hash)) {
            case 'md2':
            case 'md5':
            case 'sha1':
            case 'sha256':
            case 'sha384':
            case 'sha512':
            case 'sha224':
            case 'sha512/224':
            case 'sha512/256':
                $new->mgfHash = new Hash($hash);
                break;
            default:
                throw new UnsupportedAlgorithmException(
                    'The only supported hash algorithms are: md2, md5, sha1, sha256, sha384, sha512, sha224, sha512/224, sha512/256'
                );
        }
        $new->mgfHLen = $new->mgfHash->getLengthInBytes();

        return $new;
    }

    /**
     * Returns the MGF hash algorithm currently being used
     */
    public function getMGFHash(): Hash
    {
        return clone $this->mgfHash;
    }

    /**
     * Determines the salt length
     *
     * Used by RSA::PADDING_PSS
     *
     * To quote from {@link http://tools.ietf.org/html/rfc3447#page-38 RFC3447#page-38}:
     *
     *    Typical salt lengths in octets are hLen (the length of the output
     *    of the hash function Hash) and 0.
     */
    public function withSaltLength(?int $sLen): RSA
    {
        $new = clone $this;
        $new->sLen = $sLen;
        return $new;
    }

    /**
     * Returns the salt length currently being used
     */
    public function getSaltLength(): int
    {
        return $this->sLen !== null ? $this->sLen : $this->hLen;
    }

    /**
     * Determines the label
     *
     * Used by RSA::PADDING_OAEP
     *
     * To quote from {@link http://tools.ietf.org/html/rfc3447#page-17 RFC3447#page-17}:
     *
     *    Both the encryption and the decryption operations of RSAES-OAEP take
     *    the value of a label L as input.  In this version of PKCS #1, L is
     *    the empty string; other uses of the label are outside the scope of
     *    this document.
     */
    public function withLabel(string $label): RSA
    {
        $new = clone $this;
        $new->label = $label;
        return $new;
    }

    /**
     * Returns the label currently being used
     */
    public function getLabel(): string
    {
        return $this->label;
    }

    /**
     * Determines the padding modes
     *
     * Example: $key->withPadding(RSA::ENCRYPTION_PKCS1 | RSA::SIGNATURE_PKCS1);
     */
    public function withPadding(int $padding): RSA
    {
        $masks = [
            self::ENCRYPTION_OAEP,
            self::ENCRYPTION_PKCS1,
            self::ENCRYPTION_NONE,
        ];
        $encryptedCount = 0;
        $selected = 0;
        foreach ($masks as $mask) {
            if ($padding & $mask) {
                $selected = $mask;
                $encryptedCount++;
            }
        }
        if ($encryptedCount > 1) {
            throw new InconsistentSetupException('Multiple encryption padding modes have been selected; at most only one should be selected');
        }
        $encryptionPadding = $selected;

        $masks = [
            self::SIGNATURE_PSS,
            self::SIGNATURE_RELAXED_PKCS1,
            self::SIGNATURE_PKCS1,
        ];
        $signatureCount = 0;
        $selected = 0;
        foreach ($masks as $mask) {
            if ($padding & $mask) {
                $selected = $mask;
                $signatureCount++;
            }
        }
        if ($signatureCount > 1) {
            throw new InconsistentSetupException('Multiple signature padding modes have been selected; at most only one should be selected');
        }
        $signaturePadding = $selected;

        $new = clone $this;
        if ($encryptedCount) {
            $new->encryptionPadding = $encryptionPadding;
        }
        if ($signatureCount) {
            $new->signaturePadding = $signaturePadding;
        }
        return $new;
    }

    /**
     * Returns the padding currently being used
     */
    public function getPadding(): int
    {
        return $this->signaturePadding | $this->encryptionPadding;
    }

    /**
     * Enable RSA Blinding
     */
    public static function enableBlinding(): void
    {
        static::$enableBlinding = true;
    }

    /**
     * Disable RSA Blinding
     */
    public static function disableBlinding(): void
    {
        static::$enableBlinding = false;
    }

    /**
     * Handles OpenSSL encryption / decryption / signature creation / verification
     */
    protected function handleOpenSSL(string $func, string $message, ?string $signature = null): bool|null|string
    {
        $paddingType = match ($func) {
            'openssl_verify', 'openssl_sign' => 'signaturePadding',
            // 'openssl_public_encrypt', 'openssl_private_decrypt'
            default => 'encryptionPadding'
        };

        if (self::$forcedEngine === 'libsodium') {
            throw new BadConfigurationException('Engine libsodium is not supported for RSA');
        }

        if ((isset(self::$forcedEngine) && self::$forcedEngine !== 'PHP') && $this->$paddingType === self::SIGNATURE_RELAXED_PKCS1) {
            throw new BadConfigurationException('Only the PHP engine can be used with relaxed PKCS1 padding');
        }

        if (self::$forcedEngine !== 'PHP') {
            if (self::$forcedEngine === 'OpenSSL' && !function_exists($func)) {
                throw new BadConfigurationException('Engine OpenSSL is forced but unavailable for RSA');
            }
            if ($this->$paddingType === self::SIGNATURE_PSS) {
                switch (true) {
                    case !defined('OPENSSL_PKCS1_PSS_PADDING'):
                        $error = 'Engine OpenSSL is forced but PSS encryption requires PHP >= 8.5.0';
                        break;
                    case $this->hash->getHash() !== $this->mgfHash->getHash():
                        $error = 'Engine OpenSSL is forced but can\'t be used because the Hash and MGF Hash do not match';
                        break;
                    case $this->getSaltLength() !== $this->hLen:
                        $error = 'Engine OpenSSL is forced but can\'t be used because the salt length doesn\'t match the hash length';
                }
            }
            if ($this->$paddingType === self::ENCRYPTION_OAEP) {
                switch (true) {
                    case $this->hash->getHash() !== $this->mgfHash->getHash():
                        $error = 'Engine OpenSSL is forced but can\'t be used because the Hash and MGF Hash do not match';
                        break;
                    case $this->hash->getHash() !== 'sha1' && PHP_VERSION_ID < 80500:
                        $error = 'Engine OpenSSL is forced but non-sha1 hashes are only supported on PHP 8.5.0+';
                        break;
                    case strlen($this->label):
                        $error = 'Engine OpenSSL is forced but can\'t be used because the label is not the empty string';
                }
            }
            if (isset($error)) {
                if (self::$forcedEngine === 'OpenSSL') {
                    throw new BadConfigurationException($error);
                }
            } elseif ($paddingType === 'signaturePadding') {
                switch (true) {
                    case $this->signaturePadding === self::SIGNATURE_PSS && defined('OPENSSL_PKCS1_PSS_PADDING'):
                    case $this->signaturePadding !== self::SIGNATURE_PSS && function_exists($func):
                        $key = $this instanceof PrivateKey ?
                            $this->withPassword()->toString('PKCS8') :
                            $this->toString('PKCS8');
                        if ($func === 'openssl_sign' && str_contains($key, 'PUBLIC')) {
                            if (self::$forcedEngine === 'OpenSSL') {
                                throw new BadConfigurationException('Engine OpenSSL is forced but cannot be used because the private key does not have the prime components within it');
                            }
                            break;
                        }
                        $hash = $this->hash->getHash();

                        $result = $this->signaturePadding === self::SIGNATURE_PSS ?
                            $func($message, $signature, $key, $hash, OPENSSL_PKCS1_PSS_PADDING) :
                            $func($message, $signature, $key, $hash);

                        if ($func === 'openssl_verify' && $result !== -1 && $result !== false) {
                            return (bool) $result;
                        }
                        if ($result) {
                            return $signature;
                        }
                        if (self::$forcedEngine === 'OpenSSL') {
                            throw new BadConfigurationException('Engine OpenSSL is forced but was unable to create signature because of ' . openssl_error_string());
                        }
                }
            } else {
                if ($this->encryptionPadding !== self::ENCRYPTION_OAEP || PHP_VERSION_ID >= 80500) {
                    $key = $this->toString('PKCS8');
                    if ($func === 'openssl_private_decrypt' && str_contains($key, 'PUBLIC')) {
                        if ($this->encryptionPadding === self::ENCRYPTION_OAEP) {
                            if (self::$forcedEngine === 'OpenSSL') {
                                throw new BadConfigurationException('Engine OpenSSL is forced but cannot be used because openssl_public_decrypt() doesn\'t have a hash parameter like openssl_private_decrypt() does');
                            }
                            return null;
                        }
                        $func = 'openssl_public_decrypt';
                    }
                    $hash = $this->hash->getHash();
                    $output = '';
                    switch ($this->encryptionPadding) {
                        case self::ENCRYPTION_NONE:
                        case self::ENCRYPTION_PKCS1:
                            $padding = $this->encryptionPadding === self::ENCRYPTION_NONE ? OPENSSL_NO_PADDING : OPENSSL_PKCS1_PADDING;
                            $result = $func($message, $output, $key, $padding);
                            break;
                        //case self::ENCRYPTION_OAEP:
                        default:
                            $result = $func($message, $output, $key, OPENSSL_PKCS1_OAEP_PADDING, $hash);
                    }
                    if ($result) {
                        return $output;
                    }
                }
            }
            return null;
        }

        return null;
    }
}
