<?php

/**
 * Base Class for all \phpseclib4\Crypt\* cipher classes
 *
 * PHP version 5
 *
 * Internally for phpseclib developers:
 *  If you plan to add a new cipher class, please note following rules:
 *
 *  - The new \phpseclib4\Crypt\* cipher class should extend \phpseclib4\Crypt\Common\SymmetricKey
 *
 *  - Following methods are then required to be overridden/overloaded:
 *
 *    - encryptBlock()
 *
 *    - decryptBlock()
 *
 *    - setupKey()
 *
 *  - All other methods are optional to be overridden/overloaded
 *
 *  - Look at the source code of the current ciphers how they extend \phpseclib4\Crypt\Common\SymmetricKey
 *    and take one of them as a start up for the new cipher class.
 *
 *  - Please read all the other comments/notes/hints here also for each class var/method
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @author    Hans-Juergen Petrich <petrich@tronic-media.com>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\Common;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\Blowfish;
use phpseclib4\Crypt\Hash;
use phpseclib4\Exception\BadDecryptionException;
use phpseclib4\Exception\BadMethodCallException;
use phpseclib4\Exception\BadModeException;
use phpseclib4\Exception\InconsistentSetupException;
use phpseclib4\Exception\InsufficientSetupException;
use phpseclib4\Exception\LengthException;
use phpseclib4\Exception\LogicException;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\Math\BigInteger;
use phpseclib4\Math\BinaryField;
use phpseclib4\Math\PrimeField;

/**
 * Base Class for all \phpseclib4\Crypt\* cipher classes
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @author  Hans-Juergen Petrich <petrich@tronic-media.com>
 */
abstract class SymmetricKey
{
    use Traits\PKCS12Helper;

    /**
     * Encrypt / decrypt using the Counter mode.
     *
     * Set to -1 since that's what Crypt/Random.php uses to index the CTR mode.
     *
     * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
     * @see \phpseclib4\Crypt\Common\SymmetricKey::encrypt()
     * @see \phpseclib4\Crypt\Common\SymmetricKey::decrypt()
     */
    public const MODE_CTR = -1;
    /**
     * Encrypt / decrypt using the Electronic Code Book mode.
     *
     * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29
     * @see \phpseclib4\Crypt\Common\SymmetricKey::encrypt()
     * @see \phpseclib4\Crypt\Common\SymmetricKey::decrypt()
     */
    public const MODE_ECB = 1;
    /**
     * Encrypt / decrypt using the Code Book Chaining mode.
     *
     * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
     * @see \phpseclib4\Crypt\Common\SymmetricKey::encrypt()
     * @see \phpseclib4\Crypt\Common\SymmetricKey::decrypt()
     */
    public const MODE_CBC = 2;
    /**
     * Encrypt / decrypt using the Cipher Feedback mode.
     *
     * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
     * @see \phpseclib4\Crypt\Common\SymmetricKey::encrypt()
     * @see \phpseclib4\Crypt\Common\SymmetricKey::decrypt()
     */
    public const MODE_CFB = 3;
    /**
     * Encrypt / decrypt using the Cipher Feedback mode (8bit)
     *
     * @see \phpseclib4\Crypt\Common\SymmetricKey::encrypt()
     * @see \phpseclib4\Crypt\Common\SymmetricKey::decrypt()
     */
    public const MODE_CFB8 = 7;
    /**
     * Encrypt / decrypt using the Output Feedback mode (8bit)
     *
     * @see \phpseclib4\Crypt\Common\SymmetricKey::encrypt()
     * @see \phpseclib4\Crypt\Common\SymmetricKey::decrypt()
     */
    public const MODE_OFB8 = 8;
    /**
     * Encrypt / decrypt using the Output Feedback mode.
     *
     * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29
     * @see \phpseclib4\Crypt\Common\SymmetricKey::encrypt()
     * @see \phpseclib4\Crypt\Common\SymmetricKey::decrypt()
     */
    public const MODE_OFB = 4;
    /**
     * Encrypt / decrypt using Galois/Counter mode.
     *
     * @link https://en.wikipedia.org/wiki/Galois/Counter_Mode
     * @see \phpseclib4\Crypt\Common\SymmetricKey::encrypt()
     * @see \phpseclib4\Crypt\Common\SymmetricKey::decrypt()
     */
    public const MODE_GCM = 5;
    /**
     * Encrypt / decrypt using streaming mode.
     *
     * @see \phpseclib4\Crypt\Common\SymmetricKey::encrypt()
     * @see \phpseclib4\Crypt\Common\SymmetricKey::decrypt()
     */
    public const MODE_STREAM = 6;

    /**
     * Mode Map
     *
     * @see \phpseclib4\Crypt\Common\SymmetricKey::__construct()
     */
    public const MODE_MAP = [
        'ctr'    => self::MODE_CTR,
        'ecb'    => self::MODE_ECB,
        'cbc'    => self::MODE_CBC,
        'cfb'    => self::MODE_CFB,
        'cfb8'   => self::MODE_CFB8,
        'ofb'    => self::MODE_OFB,
        'ofb8'   => self::MODE_OFB8,
        'gcm'    => self::MODE_GCM,
        'stream' => self::MODE_STREAM,
    ];

    /**
     * Base value for the internal implementation $engine switch
     *
     * @see \phpseclib4\Crypt\Common\SymmetricKey::__construct()
     */
    public const ENGINE_INTERNAL = 1;
    /**
     * Base value for the eval() implementation $engine switch
     *
     * @see \phpseclib4\Crypt\Common\SymmetricKey::__construct()
     */
    public const ENGINE_EVAL = 2;
    /**
     * Base value for the openssl implementation $engine switch
     *
     * @see \phpseclib4\Crypt\Common\SymmetricKey::__construct()
     */
    public const ENGINE_OPENSSL = 4;
    /**
     * Base value for the libsodium implementation $engine switch
     *
     * @see \phpseclib4\Crypt\Common\SymmetricKey::__construct()
     */
    public const ENGINE_LIBSODIUM = 5;
    /**
     * Base value for the openssl / gcm implementation $engine switch
     *
     * @see \phpseclib4\Crypt\Common\SymmetricKey::__construct()
     */
    public const ENGINE_OPENSSL_GCM = 6;

    /**
     * Engine Reverse Map
     *
     * @see \phpseclib4\Crypt\Common\SymmetricKey::getEngine()
     */
    public const ENGINE_MAP = [
        self::ENGINE_INTERNAL    => 'PHP',
        self::ENGINE_EVAL        => 'Eval',
        self::ENGINE_OPENSSL     => 'OpenSSL',
        self::ENGINE_LIBSODIUM   => 'libsodium',
        self::ENGINE_OPENSSL_GCM => 'OpenSSL (GCM)',
    ];

    /**
     * The Encryption Mode
     *
     * @see self::__construct()
     * @var int
     */
    protected $mode;

    /**
     * The Block Length of the block cipher
     *
     * @var int
     */
    protected $block_size = 16;

    /**
     * The Key
     *
     * @see self::setKey()
     * @var string
     */
    protected $key = false;

    /**
     * HMAC Key
     *
     * @see self::setupGCM()
     * @var null|string
     */
    private $hKey = null;

    /**
     * The Initialization Vector
     *
     * @see self::setIV()
     * @var string
     */
    protected $iv = false;

    /**
     * A "sliding" Initialization Vector
     *
     * @see self::enableContinuousBuffer()
     * @see self::clearBuffers()
     * @var string
     */
    protected $encryptIV;

    /**
     * A "sliding" Initialization Vector
     *
     * @see self::enableContinuousBuffer()
     * @see self::clearBuffers()
     * @var string
     */
    protected $decryptIV;

    /**
     * Continuous Buffer status
     *
     * @see self::enableContinuousBuffer()
     * @var bool
     */
    protected $continuousBuffer = false;

    /**
     * Encryption buffer for CTR, OFB and CFB modes
     *
     * @see self::encrypt()
     * @see self::clearBuffers()
     * @var array
     */
    protected $enbuffer;

    /**
     * Decryption buffer for CTR, OFB and CFB modes
     *
     * @see self::decrypt()
     * @see self::clearBuffers()
     * @var array
     */
    protected $debuffer;

    /**
     * Does internal cipher state need to be (re)initialized?
     *
     * @see self::setKey()
     * @see self::setIV()
     * @see self::disableContinuousBuffer()
     * @var bool
     */
    protected $changed = true;

    /**
     * Does Eval engie need to be (re)initialized?
     *
     * @see self::setup()
     * @var bool
     */
    protected $nonIVChanged = true;

    /**
     * Padding status
     *
     * @see self::enablePadding()
     * @var bool
     */
    private $padding = true;

    /**
     * Is the mode one that is paddable?
     *
     * @see self::__construct()
     * @var bool
     */
    private $paddable = false;

    /**
     * Holds which crypt engine internaly should be use,
     * which will be determined automatically on __construct()
     *
     * Currently available $engines are:
     * - self::ENGINE_LIBSODIUM   (very fast, php-extension: libsodium, extension_loaded('libsodium') required)
     * - self::ENGINE_OPENSSL_GCM (very fast, php-extension: openssl, extension_loaded('openssl') required)
     * - self::ENGINE_OPENSSL     (very fast, php-extension: openssl, extension_loaded('openssl') required)
     * - self::ENGINE_EVAL        (medium, pure php-engine, no php-extension required)
     * - self::ENGINE_INTERNAL    (slower, pure php-engine, no php-extension required)
     *
     * @see self::setEngine()
     * @see self::encrypt()
     * @see self::decrypt()
     * @var int
     */
    protected $engine;

    /**
     * Holds the preferred crypt engine
     *
     * @see self::setEngine()
     * @see self::setPreferredEngine()
     * @var int
     */
    private $preferredEngine;

    /**
     * The openssl specific name of the cipher
     *
     * Only used if $engine == self::ENGINE_OPENSSL
     *
     * @link http://www.php.net/openssl-get-cipher-methods
     * @var string
     */
    protected $cipher_name_openssl;

    /**
     * The openssl specific name of the cipher in ECB mode
     *
     * If OpenSSL does not support the mode we're trying to use (CTR)
     * it can still be emulated with ECB mode.
     *
     * @link http://www.php.net/openssl-get-cipher-methods
     * @var string
     */
    protected $cipher_name_openssl_ecb;

    /**
     * The default salt used by setPassword()
     *
     * @see self::setPassword()
     * @var string
     */
    private $password_default_salt = 'phpseclib/salt';

    /**
     * The name of the performance-optimized callback function
     *
     * Used by encrypt() / decrypt()
     * only if $engine == self::ENGINE_INTERNAL
     *
     * @see self::encrypt()
     * @see self::decrypt()
     * @see self::setupInlineCrypt()
     * @var Callback
     */
    protected $inline_crypt;

    /**
     * If OpenSSL can be used in ECB but not in CTR we can emulate CTR
     *
     * @see self::openssl_ctr_process()
     * @var bool
     */
    private $openssl_emulate_ctr = false;

    /**
     * Has the key length explicitly been set or should it be derived from the key, itself?
     *
     * @see self::setKeyLength()
     * @var bool
     */
    protected $explicit_key_length = false;

    /**
     * Hash subkey for GHASH
     *
     * @see self::setupGCM()
     * @see self::ghash()
     * @var BinaryField\Integer
     */
    private $h;

    /**
     * Additional authenticated data
     *
     * @var string
     */
    protected $aad = '';

    /**
     * Authentication Tag produced after a round of encryption
     *
     * @var string
     */
    protected $newtag = false;

    /**
     * Authentication Tag to be verified during decryption
     *
     * @var string
     */
    protected $oldtag = false;

    /**
     * GCM Binary Field
     *
     * @see self::__construct()
     * @see self::ghash()
     * @var BinaryField
     */
    private static $gcmField;

    /**
     * Poly1305 Prime Field
     *
     * @see self::enablePoly1305()
     * @see self::poly1305()
     * @var PrimeField
     */
    private static $poly1305Field;

    /**
     * Poly1305 Key
     *
     * @see self::setPoly1305Key()
     * @see self::poly1305()
     * @var string
     */
    protected $poly1305Key;

    /**
     * Poly1305 Flag
     *
     * @see self::setPoly1305Key()
     * @see self::enablePoly1305()
     * @var boolean
     */
    protected $usePoly1305 = false;

    /**
     * The Original Initialization Vector
     *
     * GCM uses the nonce to build the IV but we want to be able to distinguish between nonce-derived
     * IV's and user-set IV's
     *
     * @see self::setIV()
     * @var string
     */
    private $origIV = false;

    /**
     * Nonce
     *
     * Only used with GCM. We could re-use setIV() but nonce's can be of a different length and
     * toggling between GCM and other modes could be more complicated if we re-used setIV()
     *
     * @see self::setNonce()
     * @var string
     */
    protected $nonce = false;

    private array $metadata = [];

    /**
     * Default Constructor.
     *
     * $mode could be:
     *
     * - ecb
     *
     * - cbc
     *
     * - ctr
     *
     * - cfb
     *
     * - cfb8
     *
     * - ofb
     *
     * - ofb8
     *
     * - gcm
     *
     * @throws BadModeException if an invalid / unsupported mode is provided
     */
    public function __construct(string $mode)
    {
        $mode = strtolower($mode);
        // necessary because of 5.6 compatibility; we can't do isset(self::MODE_MAP[$mode]) in 5.6
        $map = self::MODE_MAP;
        if (!isset($map[$mode])) {
            throw new BadModeException('No valid mode has been specified');
        }

        $mode = self::MODE_MAP[$mode];

        // $mode dependent settings
        switch ($mode) {
            case self::MODE_ECB:
            case self::MODE_CBC:
                $this->paddable = true;
                break;
            case self::MODE_CTR:
            case self::MODE_CFB:
            case self::MODE_CFB8:
            case self::MODE_OFB:
            case self::MODE_OFB8:
            case self::MODE_STREAM:
                $this->paddable = false;
                break;
            case self::MODE_GCM:
                if ($this->block_size != 16) {
                    throw new BadModeException('GCM is only valid for block ciphers with a block size of 128 bits');
                }
                if (!isset(self::$gcmField)) {
                    self::$gcmField = new BinaryField(128, 7, 2, 1, 0);
                }
                $this->paddable = false;
                break;
            default:
                throw new BadModeException('No valid mode has been specified');
        }

        $this->mode = $mode;

        static::initialize_static_variables();
    }

    /**
     * Initialize static variables
     */
    protected static function initialize_static_variables(): void
    {
    }

    /**
     * Sets the initialization vector.
     *
     * setIV() is not required when ecb or gcm modes are being used.
     *
     * {@internal Can be overwritten by a sub class, but does not have to be}
     *
     * @throws LengthException if the IV length isn't equal to the block size
     * @throws BadMethodCallException if an IV is provided when one shouldn't be
     */
    public function setIV(string $iv): void
    {
        if ($this->mode == self::MODE_ECB) {
            throw new BadMethodCallException('This mode does not require an IV.');
        }

        if ($this->mode == self::MODE_GCM) {
            throw new BadMethodCallException('Use setNonce instead');
        }

        if (!$this->usesIV()) {
            throw new BadMethodCallException('This algorithm does not use an IV.');
        }

        if (strlen($iv) != $this->block_size) {
            throw new LengthException('Received initialization vector of size ' . strlen($iv) . ', but size ' . $this->block_size . ' is required');
        }

        $this->iv = $this->origIV = $iv;
        $this->changed = true;
    }

    /**
     * Enables Poly1305 mode.
     *
     * Once enabled Poly1305 cannot be disabled.
     *
     * @throws BadMethodCallException if Poly1305 is enabled whilst in GCM mode
     */
    public function enablePoly1305(): void
    {
        if ($this->mode == self::MODE_GCM) {
            throw new BadMethodCallException('Poly1305 cannot be used in GCM mode');
        }

        $this->usePoly1305 = true;
    }

    /**
     * Enables Poly1305 mode.
     *
     * Once enabled Poly1305 cannot be disabled. If $key is not passed then an attempt to call createPoly1305Key
     * will be made.
     *
     * @param string|null $key optional
     * @throws LengthException if the key isn't long enough
     * @throws BadMethodCallException if Poly1305 is enabled whilst in GCM mode
     */
    public function setPoly1305Key(?string $key = null): void
    {
        if ($this->mode == self::MODE_GCM) {
            throw new BadMethodCallException('Poly1305 cannot be used in GCM mode');
        }

        if (!is_string($key) || strlen($key) != 32) {
            throw new LengthException('The Poly1305 key must be 32 bytes long (256 bits)');
        }

        if (!isset(self::$poly1305Field)) {
            // 2^130-5
            self::$poly1305Field = new PrimeField(new BigInteger('3fffffffffffffffffffffffffffffffb', 16));
        }

        $this->poly1305Key = $key;
        $this->usePoly1305 = true;
    }

    /**
     * Sets the nonce.
     *
     * setNonce() is only required when gcm is used
     *
     * @throws BadMethodCallException if an nonce is provided when one shouldn't be
     */
    public function setNonce(string $nonce): void
    {
        if ($this->mode != self::MODE_GCM) {
            throw new BadMethodCallException('Nonces are only used in GCM mode.');
        }

        $this->nonce = $nonce;
        $this->setEngine();
    }

    /**
     * Sets additional authenticated data
     *
     * setAAD() is only used by gcm or in poly1305 mode
     *
     * @throws BadMethodCallException if mode isn't GCM or if poly1305 isn't being utilized
     */
    public function setAAD(string $aad): void
    {
        if ($this->mode != self::MODE_GCM && !$this->usePoly1305) {
            throw new BadMethodCallException('Additional authenticated data is only utilized in GCM mode or with Poly1305');
        }

        $this->aad = $aad;
    }

    /**
     * Returns whether or not the algorithm uses an IV
     */
    public function usesIV(): bool
    {
        return $this->mode != self::MODE_GCM && $this->mode != self::MODE_ECB;
    }

    /**
     * Returns whether or not the algorithm uses a nonce
     */
    public function usesNonce(): bool
    {
        return $this->mode == self::MODE_GCM;
    }

    /**
     * Returns the current key length in bits
     */
    public function getKeyLength(): int
    {
        return $this->key_length << 3;
    }

    /**
     * Returns the current block length in bits
     */
    public function getBlockLength(): int
    {
        return $this->block_size << 3;
    }

    /**
     * Returns the current block length in bytes
     */
    public function getBlockLengthInBytes(): int
    {
        return $this->block_size;
    }

    /**
     * Sets the key length.
     *
     * Keys with explicitly set lengths need to be treated accordingly
     */
    public function setKeyLength(int $length): void
    {
        $this->explicit_key_length = $length >> 3;

        if (is_string($this->key) && strlen($this->key) != $this->explicit_key_length) {
            $this->key = false;
            throw new InconsistentSetupException('Key has already been set and is not ' . $this->explicit_key_length . ' bytes long');
        }
    }

    /**
     * Sets the key.
     *
     * The min/max length(s) of the key depends on the cipher which is used.
     * If the key not fits the length(s) of the cipher it will paded with null bytes
     * up to the closest valid key length.  If the key is more than max length,
     * we trim the excess bits.
     *
     * If the key is not explicitly set, it'll be assumed to be all null bytes.
     *
     * {@internal Could, but not must, extend by the child Crypt_* class}
     */
    public function setKey(string $key): void
    {
        if ($this->explicit_key_length !== false && strlen($key) != $this->explicit_key_length) {
            throw new InconsistentSetupException('Key length has already been set to ' . $this->explicit_key_length . ' bytes and this key is ' . strlen($key) . ' bytes');
        }

        $this->key = $key;
        $this->key_length = strlen($key);
        $this->setEngine();
    }

    /**
     * Sets the password.
     *
     * Depending on what $method is set to, setPassword()'s (optional) parameters are as follows:
     *     {@link http://en.wikipedia.org/wiki/PBKDF2 pbkdf2} or pbkdf1:
     *         $hash, $salt, $count, $dkLen
     *
     *         Where $hash (default = sha1) currently supports the following hashes: see: Crypt/Hash.php
     *     {@link https://en.wikipedia.org/wiki/Bcrypt bcypt}:
     *         $salt, $rounds, $keylen
     *
     *         This is a modified version of bcrypt used by OpenSSH.
     *
     * {@internal Could, but not must, extend by the child Crypt_* class}
     *
     * @throws LengthException if pbkdf1 is being used and the derived key length exceeds the hash length
     * @throws RuntimeException if bcrypt is being used and a salt isn't provided
     * @see Crypt/Hash.php
     */
    public function setPassword(string $password, string $method = 'pbkdf2', int|string ...$func_args): bool
    {
        $key = '';

        $method = strtolower($method);
        switch ($method) {
            case 'bcrypt':
                if (!isset($func_args[2])) {
                    throw new RuntimeException('A salt must be provided for bcrypt to work');
                }

                $salt = $func_args[0];

                $rounds = $func_args[1] ?? 16;
                $keylen = $func_args[2] ?? $this->key_length;

                $key = Blowfish::bcrypt_pbkdf($password, $salt, $keylen + $this->block_size, $rounds);

                $this->setKey(substr($key, 0, $keylen));
                $this->setIV(substr($key, $keylen));

                return true;
            case 'pkcs12': // from https://tools.ietf.org/html/rfc7292#appendix-B.2
            case 'pbkdf1':
            case 'pbkdf2':
                // Hash function
                $hash = isset($func_args[0]) ? strtolower($func_args[0]) : 'sha1';
                $hashObj = new Hash();
                $hashObj->setHash($hash);

                // WPA and WPA2 use the SSID as the salt
                $salt = $func_args[1] ?? $this->password_default_salt;

                // RFC2898#section-4.2 uses 1,000 iterations by default
                // WPA and WPA2 use 4,096.
                $count = $func_args[2] ?? 1000;

                // Keylength
                if (isset($func_args[3])) {
                    if ($func_args[3] <= 0) {
                        throw new LengthException('Derived key length cannot be longer 0 or less');
                    }
                    $dkLen = $func_args[3];
                } else {
                    $key_length = $this->explicit_key_length !== false ? $this->explicit_key_length : $this->key_length;
                    $dkLen = $method == 'pbkdf1' ? 2 * $key_length : $key_length;
                }

                switch (true) {
                    case $method == 'pkcs12':
                        /*
                         In this specification, however, all passwords are created from
                         BMPStrings with a NULL terminator.  This means that each character in
                         the original BMPString is encoded in 2 bytes in big-endian format
                         (most-significant byte first).  There are no Unicode byte order
                         marks.  The 2 bytes produced from the last character in the BMPString
                         are followed by 2 additional bytes with the value 0x00.

                         -- https://tools.ietf.org/html/rfc7292#appendix-B.1
                         */
                        $password = "\0" . chunk_split($password, 1, "\0") . "\0";

                        /*
                         This standard specifies 3 different values for the ID byte mentioned
                         above:

                         1.  If ID=1, then the pseudorandom bits being produced are to be used
                             as key material for performing encryption or decryption.

                         2.  If ID=2, then the pseudorandom bits being produced are to be used
                             as an IV (Initial Value) for encryption or decryption.

                         3.  If ID=3, then the pseudorandom bits being produced are to be used
                             as an integrity key for MACing.
                         */
                        // Construct a string, D (the "diversifier"), by concatenating v/8
                        // copies of ID.
                        $blockLength = $hashObj->getBlockLengthInBytes();
                        $d1 = str_repeat(chr(1), $blockLength);
                        $d2 = str_repeat(chr(2), $blockLength);
                        $s = '';
                        if (strlen($salt)) {
                            while (strlen($s) < $blockLength) {
                                $s .= $salt;
                            }
                        }
                        $s = substr($s, 0, $blockLength);

                        $p = '';
                        if (strlen($password)) {
                            while (strlen($p) < $blockLength) {
                                $p .= $password;
                            }
                        }
                        $p = substr($p, 0, $blockLength);

                        $i = $s . $p;

                        $this->setKey(self::pkcs12helper($dkLen, $hashObj, $i, $d1, $count));
                        if ($this->usesIV()) {
                            $this->setIV(self::pkcs12helper($this->block_size, $hashObj, $i, $d2, $count));
                        }

                        return true;
                    case $method == 'pbkdf1':
                        if ($dkLen > $hashObj->getLengthInBytes()) {
                            throw new LengthException('Derived key length cannot be longer than the hash length');
                        }
                        $t = $password . $salt;
                        for ($i = 0; $i < $count; ++$i) {
                            $t = $hashObj->hash($t);
                        }
                        $key = substr($t, 0, $dkLen);

                        $this->setKey(substr($key, 0, $dkLen >> 1));
                        if ($this->usesIV()) {
                            $this->setIV(substr($key, $dkLen >> 1));
                        }

                        return true;
                    case !in_array($hash, hash_algos()):
                        $i = 1;
                        $hashObj->setKey($password);
                        while (strlen($key) < $dkLen) {
                            $f = $u = $hashObj->hash($salt . pack('N', $i++));
                            for ($j = 2; $j <= $count; ++$j) {
                                $u = $hashObj->hash($u);
                                $f ^= $u;
                            }
                            $key .= $f;
                        }
                        $key = substr($key, 0, $dkLen);
                        break;
                    default:
                        $key = hash_pbkdf2($hash, $password, $salt, $count, $dkLen, true);
                }
                break;
            default:
                throw new UnsupportedAlgorithmException($method . ' is not a supported password hashing method');
        }

        $this->setKey($key);

        return true;
    }

    /**
     * Encrypts a message.
     *
     * $plaintext will be padded with additional bytes such that it's length is a multiple of the block size. Other cipher
     * implementations may or may not pad in the same manner.  Other common approaches to padding and the reasons why it's
     * necessary are discussed in the following
     * URL:
     *
     * {@link http://www.di-mgt.com.au/cryptopad.html http://www.di-mgt.com.au/cryptopad.html}
     *
     * An alternative to padding is to, separately, send the length of the file.  This is what SSH, in fact, does.
     * strlen($plaintext) will still need to be a multiple of the block size, however, arbitrary values can be added to make it that
     * length.
     *
     * {@internal Could, but not must, extend by the child Crypt_* class}
     *
     * @return string $ciphertext
     * @see self::decrypt()
     */
    public function encrypt(string $plaintext): string
    {
        if ($this->paddable) {
            $plaintext = $this->pad($plaintext);
        }

        $this->setup();

        if ($this->mode == self::MODE_GCM) {
            $oldIV = $this->iv;
            Strings::increment_str($this->iv);
            $cipher = new static('ctr');
            $cipher->setKey($this->key);
            $cipher->setIV($this->iv);
            $ciphertext = $cipher->encrypt($plaintext);

            $s = $this->ghash(
                self::nullPad128($this->aad) .
                self::nullPad128($ciphertext) .
                self::len64($this->aad) .
                self::len64($ciphertext)
            );
            $cipher->encryptIV = $this->iv = $this->encryptIV = $this->decryptIV = $oldIV;
            $this->newtag = $cipher->encrypt($s);
            return $ciphertext;
        }

        if (isset($this->poly1305Key)) {
            $cipher = clone $this;
            unset($cipher->poly1305Key);
            $this->usePoly1305 = false;
            $ciphertext = $cipher->encrypt($plaintext);
            $this->newtag = $this->poly1305($ciphertext);
            return $ciphertext;
        }

        if ($this->engine === self::ENGINE_OPENSSL) {
            switch ($this->mode) {
                case self::MODE_STREAM:
                    return openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                case self::MODE_ECB:
                    return openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                case self::MODE_CBC:
                    $result = openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->encryptIV);
                    if ($this->continuousBuffer) {
                        $this->encryptIV = substr($result, -$this->block_size);
                    }
                    return $result;
                case self::MODE_CTR:
                    return $this->openssl_ctr_process($plaintext, $this->encryptIV, $this->enbuffer);
                case self::MODE_CFB:
                    // cfb loosely routines inspired by openssl's:
                    // {@link http://cvs.openssl.org/fileview?f=openssl/crypto/modes/cfb128.c&v=1.3.2.2.2.1}
                    $ciphertext = '';
                    if ($this->continuousBuffer) {
                        $iv = &$this->encryptIV;
                        $pos = &$this->enbuffer['pos'];
                    } else {
                        $iv = $this->encryptIV;
                        $pos = 0;
                    }
                    $len = strlen($plaintext);
                    $i = 0;
                    if ($pos) {
                        $orig_pos = $pos;
                        $max = $this->block_size - $pos;
                        if ($len >= $max) {
                            $i = $max;
                            $len -= $max;
                            $pos = 0;
                        } else {
                            $i = $len;
                            $pos += $len;
                            $len = 0;
                        }
                        // ie. $i = min($max, $len), $len-= $i, $pos+= $i, $pos%= $blocksize
                        $ciphertext = substr($iv, $orig_pos) ^ $plaintext;
                        $iv = substr_replace($iv, $ciphertext, $orig_pos, $i);
                        $plaintext = substr($plaintext, $i);
                    }

                    $overflow = $len % $this->block_size;

                    if ($overflow) {
                        $ciphertext .= openssl_encrypt(substr($plaintext, 0, -$overflow) . str_repeat("\0", $this->block_size), $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
                        $iv = Strings::pop($ciphertext, $this->block_size);

                        $size = $len - $overflow;
                        $block = $iv ^ substr($plaintext, -$overflow);
                        $iv = substr_replace($iv, $block, 0, $overflow);
                        $ciphertext .= $block;
                        $pos = $overflow;
                    } elseif ($len) {
                        $ciphertext = openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
                        $iv = substr($ciphertext, -$this->block_size);
                    }

                    return $ciphertext;
                case self::MODE_CFB8:
                    $ciphertext = openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->encryptIV);
                    if ($this->continuousBuffer) {
                        if (($len = strlen($ciphertext)) >= $this->block_size) {
                            $this->encryptIV = substr($ciphertext, -$this->block_size);
                        } else {
                            $this->encryptIV = substr($this->encryptIV, $len - $this->block_size) . substr($ciphertext, -$len);
                        }
                    }
                    return $ciphertext;
                case self::MODE_OFB8:
                    $ciphertext = '';
                    $len = strlen($plaintext);
                    $iv = $this->encryptIV;

                    for ($i = 0; $i < $len; ++$i) {
                        $xor = openssl_encrypt($iv, $this->cipher_name_openssl_ecb, $this->key, $this->openssl_options, $this->decryptIV);
                        $ciphertext .= $plaintext[$i] ^ $xor;
                        $iv = substr($iv, 1) . $xor[0];
                    }

                    if ($this->continuousBuffer) {
                        $this->encryptIV = $iv;
                    }
                    break;
                case self::MODE_OFB:
                    return $this->openssl_ofb_process($plaintext, $this->encryptIV, $this->enbuffer);
            }
        }

        if ($this->engine === self::ENGINE_EVAL) {
            $inline = $this->inline_crypt;
            return $inline('encrypt', $plaintext);
        }

        $buffer = &$this->enbuffer;
        $block_size = $this->block_size;
        $ciphertext = '';
        switch ($this->mode) {
            case self::MODE_ECB:
                for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
                    $ciphertext .= $this->encryptBlock(substr($plaintext, $i, $block_size));
                }
                break;
            case self::MODE_CBC:
                $xor = $this->encryptIV;
                for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
                    $block = substr($plaintext, $i, $block_size);
                    $block = $this->encryptBlock($block ^ $xor);
                    $xor = $block;
                    $ciphertext .= $block;
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                }
                break;
            case self::MODE_CTR:
                $xor = $this->encryptIV;
                if (strlen($buffer['ciphertext'])) {
                    for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
                        $block = substr($plaintext, $i, $block_size);
                        if (strlen($block) > strlen($buffer['ciphertext'])) {
                            $buffer['ciphertext'] .= $this->encryptBlock($xor);
                            Strings::increment_str($xor);
                        }
                        $key = Strings::shift($buffer['ciphertext'], $block_size);
                        $ciphertext .= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
                        $block = substr($plaintext, $i, $block_size);
                        $key = $this->encryptBlock($xor);
                        Strings::increment_str($xor);
                        $ciphertext .= $block ^ $key;
                    }
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                    if ($start = strlen($plaintext) % $block_size) {
                        $buffer['ciphertext'] = substr($key, $start) . $buffer['ciphertext'];
                    }
                }
                break;
            case self::MODE_CFB:
                // cfb loosely routines inspired by openssl's:
                // {@link http://cvs.openssl.org/fileview?f=openssl/crypto/modes/cfb128.c&v=1.3.2.2.2.1}
                if ($this->continuousBuffer) {
                    $iv = &$this->encryptIV;
                    $pos = &$buffer['pos'];
                } else {
                    $iv = $this->encryptIV;
                    $pos = 0;
                }
                $len = strlen($plaintext);
                $i = 0;
                if ($pos) {
                    $orig_pos = $pos;
                    $max = $block_size - $pos;
                    if ($len >= $max) {
                        $i = $max;
                        $len -= $max;
                        $pos = 0;
                    } else {
                        $i = $len;
                        $pos += $len;
                        $len = 0;
                    }
                    // ie. $i = min($max, $len), $len-= $i, $pos+= $i, $pos%= $blocksize
                    $ciphertext = substr($iv, $orig_pos) ^ $plaintext;
                    $iv = substr_replace($iv, $ciphertext, $orig_pos, $i);
                }
                while ($len >= $block_size) {
                    $iv = $this->encryptBlock($iv) ^ substr($plaintext, $i, $block_size);
                    $ciphertext .= $iv;
                    $len -= $block_size;
                    $i += $block_size;
                }
                if ($len) {
                    $iv = $this->encryptBlock($iv);
                    $block = $iv ^ substr($plaintext, $i);
                    $iv = substr_replace($iv, $block, 0, $len);
                    $ciphertext .= $block;
                    $pos = $len;
                }
                break;
            case self::MODE_CFB8:
                $ciphertext = '';
                $len = strlen($plaintext);
                $iv = $this->encryptIV;

                for ($i = 0; $i < $len; ++$i) {
                    $ciphertext .= ($c = $plaintext[$i] ^ $this->encryptBlock($iv));
                    $iv = substr($iv, 1) . $c;
                }

                if ($this->continuousBuffer) {
                    if ($len >= $block_size) {
                        $this->encryptIV = substr($ciphertext, -$block_size);
                    } else {
                        $this->encryptIV = substr($this->encryptIV, $len - $block_size) . substr($ciphertext, -$len);
                    }
                }
                break;
            case self::MODE_OFB8:
                $ciphertext = '';
                $len = strlen($plaintext);
                $iv = $this->encryptIV;

                for ($i = 0; $i < $len; ++$i) {
                    $xor = $this->encryptBlock($iv);
                    $ciphertext .= $plaintext[$i] ^ $xor;
                    $iv = substr($iv, 1) . $xor[0];
                }

                if ($this->continuousBuffer) {
                    $this->encryptIV = $iv;
                }
                break;
            case self::MODE_OFB:
                $xor = $this->encryptIV;
                if (strlen($buffer['xor'])) {
                    for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
                        $block = substr($plaintext, $i, $block_size);
                        if (strlen($block) > strlen($buffer['xor'])) {
                            $xor = $this->encryptBlock($xor);
                            $buffer['xor'] .= $xor;
                        }
                        $key = Strings::shift($buffer['xor'], $block_size);
                        $ciphertext .= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
                        $xor = $this->encryptBlock($xor);
                        $ciphertext .= substr($plaintext, $i, $block_size) ^ $xor;
                    }
                    $key = $xor;
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                    if ($start = strlen($plaintext) % $block_size) {
                        $buffer['xor'] = substr($key, $start) . $buffer['xor'];
                    }
                }
                break;
            case self::MODE_STREAM:
                $ciphertext = $this->encryptBlock($plaintext);
                break;
        }

        return $ciphertext;
    }

    /**
     * Decrypts a message.
     *
     * If strlen($ciphertext) is not a multiple of the block size, null bytes will be added to the end of the string until
     * it is.
     *
     * {@internal Could, but not must, extend by the child Crypt_* class}
     *
     * @return string $plaintext
     * @throws LengthException if we're inside a block cipher and the ciphertext length is not a multiple of the block size
     * @see self::encrypt()
     */
    public function decrypt(string $ciphertext): string
    {
        if ($this->paddable && strlen($ciphertext) % $this->block_size) {
            throw new LengthException('The ciphertext length (' . strlen($ciphertext) . ') needs to be a multiple of the block size (' . $this->block_size . ')');
        }
        $this->setup();

        if ($this->mode == self::MODE_GCM || isset($this->poly1305Key)) {
            if ($this->oldtag === false) {
                throw new InsufficientSetupException('Authentication Tag has not been set');
            }

            if (isset($this->poly1305Key)) {
                $newtag = $this->poly1305($ciphertext);
            } else {
                $oldIV = $this->iv;
                Strings::increment_str($this->iv);
                $cipher = new static('ctr');
                $cipher->setKey($this->key);
                $cipher->setIV($this->iv);
                $plaintext = $cipher->decrypt($ciphertext);

                $s = $this->ghash(
                    self::nullPad128($this->aad) .
                    self::nullPad128($ciphertext) .
                    self::len64($this->aad) .
                    self::len64($ciphertext)
                );
                $cipher->encryptIV = $this->iv = $this->encryptIV = $this->decryptIV = $oldIV;
                $newtag = $cipher->encrypt($s);
            }
            if ($this->oldtag != substr($newtag, 0, strlen($newtag))) {
                $cipher = clone $this;
                unset($cipher->poly1305Key);
                $this->usePoly1305 = false;
                $plaintext = $cipher->decrypt($ciphertext);
                $this->oldtag = false;
                throw new BadDecryptionException('Derived authentication tag and supplied authentication tag do not match');
            }
            $this->oldtag = false;
            return $plaintext;
        }

        if ($this->engine === self::ENGINE_OPENSSL) {
            switch ($this->mode) {
                case self::MODE_STREAM:
                    $plaintext = openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                    break;
                case self::MODE_ECB:
                    $plaintext = openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                    break;
                case self::MODE_CBC:
                    $offset = $this->block_size;
                    $plaintext = openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->decryptIV);
                    if ($this->continuousBuffer) {
                        $this->decryptIV = substr($ciphertext, -$offset, $this->block_size);
                    }
                    break;
                case self::MODE_CTR:
                    $plaintext = $this->openssl_ctr_process($ciphertext, $this->decryptIV, $this->debuffer);
                    break;
                case self::MODE_CFB:
                    // cfb loosely routines inspired by openssl's:
                    // {@link http://cvs.openssl.org/fileview?f=openssl/crypto/modes/cfb128.c&v=1.3.2.2.2.1}
                    $plaintext = '';
                    if ($this->continuousBuffer) {
                        $iv = &$this->decryptIV;
                        $pos = &$this->debuffer['pos'];
                    } else {
                        $iv = $this->decryptIV;
                        $pos = 0;
                    }
                    $len = strlen($ciphertext);
                    $i = 0;
                    if ($pos) {
                        $orig_pos = $pos;
                        $max = $this->block_size - $pos;
                        if ($len >= $max) {
                            $i = $max;
                            $len -= $max;
                            $pos = 0;
                        } else {
                            $i = $len;
                            $pos += $len;
                            $len = 0;
                        }
                        // ie. $i = min($max, $len), $len-= $i, $pos+= $i, $pos%= $this->blocksize
                        $plaintext = substr($iv, $orig_pos) ^ $ciphertext;
                        $iv = substr_replace($iv, substr($ciphertext, 0, $i), $orig_pos, $i);
                        $ciphertext = substr($ciphertext, $i);
                    }
                    $overflow = $len % $this->block_size;
                    if ($overflow) {
                        $plaintext .= openssl_decrypt(substr($ciphertext, 0, -$overflow), $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
                        if ($len - $overflow) {
                            $iv = substr($ciphertext, -$overflow - $this->block_size, -$overflow);
                        }
                        $iv = openssl_encrypt(str_repeat("\0", $this->block_size), $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
                        $plaintext .= $iv ^ substr($ciphertext, -$overflow);
                        $iv = substr_replace($iv, substr($ciphertext, -$overflow), 0, $overflow);
                        $pos = $overflow;
                    } elseif ($len) {
                        $plaintext .= openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
                        $iv = substr($ciphertext, -$this->block_size);
                    }
                    break;
                case self::MODE_CFB8:
                    $plaintext = openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->decryptIV);
                    if ($this->continuousBuffer) {
                        if (($len = strlen($ciphertext)) >= $this->block_size) {
                            $this->decryptIV = substr($ciphertext, -$this->block_size);
                        } else {
                            $this->decryptIV = substr($this->decryptIV, $len - $this->block_size) . substr($ciphertext, -$len);
                        }
                    }
                    break;
                case self::MODE_OFB8:
                    $plaintext = '';
                    $len = strlen($ciphertext);
                    $iv = $this->decryptIV;

                    for ($i = 0; $i < $len; ++$i) {
                        $xor = openssl_encrypt($iv, $this->cipher_name_openssl_ecb, $this->key, $this->openssl_options, $this->decryptIV);
                        $plaintext .= $ciphertext[$i] ^ $xor;
                        $iv = substr($iv, 1) . $xor[0];
                    }

                    if ($this->continuousBuffer) {
                        $this->decryptIV = $iv;
                    }
                    break;
                case self::MODE_OFB:
                    $plaintext = $this->openssl_ofb_process($ciphertext, $this->decryptIV, $this->debuffer);
            }

            return $this->paddable ? $this->unpad($plaintext) : $plaintext;
        }

        if ($this->engine === self::ENGINE_EVAL) {
            $inline = $this->inline_crypt;
            return $inline('decrypt', $ciphertext);
        }

        $block_size = $this->block_size;

        $buffer = &$this->debuffer;
        $plaintext = '';
        switch ($this->mode) {
            case self::MODE_ECB:
                for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
                    $plaintext .= $this->decryptBlock(substr($ciphertext, $i, $block_size));
                }
                break;
            case self::MODE_CBC:
                $xor = $this->decryptIV;
                for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
                    $block = substr($ciphertext, $i, $block_size);
                    $plaintext .= $this->decryptBlock($block) ^ $xor;
                    $xor = $block;
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                }
                break;
            case self::MODE_CTR:
                $xor = $this->decryptIV;
                if (strlen($buffer['ciphertext'])) {
                    for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
                        $block = substr($ciphertext, $i, $block_size);
                        if (strlen($block) > strlen($buffer['ciphertext'])) {
                            $buffer['ciphertext'] .= $this->encryptBlock($xor);
                            Strings::increment_str($xor);
                        }
                        $key = Strings::shift($buffer['ciphertext'], $block_size);
                        $plaintext .= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
                        $block = substr($ciphertext, $i, $block_size);
                        $key = $this->encryptBlock($xor);
                        Strings::increment_str($xor);
                        $plaintext .= $block ^ $key;
                    }
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                    if ($start = strlen($ciphertext) % $block_size) {
                        $buffer['ciphertext'] = substr($key, $start) . $buffer['ciphertext'];
                    }
                }
                break;
            case self::MODE_CFB:
                if ($this->continuousBuffer) {
                    $iv = &$this->decryptIV;
                    $pos = &$buffer['pos'];
                } else {
                    $iv = $this->decryptIV;
                    $pos = 0;
                }
                $len = strlen($ciphertext);
                $i = 0;
                if ($pos) {
                    $orig_pos = $pos;
                    $max = $block_size - $pos;
                    if ($len >= $max) {
                        $i = $max;
                        $len -= $max;
                        $pos = 0;
                    } else {
                        $i = $len;
                        $pos += $len;
                        $len = 0;
                    }
                    // ie. $i = min($max, $len), $len-= $i, $pos+= $i, $pos%= $blocksize
                    $plaintext = substr($iv, $orig_pos) ^ $ciphertext;
                    $iv = substr_replace($iv, substr($ciphertext, 0, $i), $orig_pos, $i);
                }
                while ($len >= $block_size) {
                    $iv = $this->encryptBlock($iv);
                    $cb = substr($ciphertext, $i, $block_size);
                    $plaintext .= $iv ^ $cb;
                    $iv = $cb;
                    $len -= $block_size;
                    $i += $block_size;
                }
                if ($len) {
                    $iv = $this->encryptBlock($iv);
                    $plaintext .= $iv ^ substr($ciphertext, $i);
                    $iv = substr_replace($iv, substr($ciphertext, $i), 0, $len);
                    $pos = $len;
                }
                break;
            case self::MODE_CFB8:
                $plaintext = '';
                $len = strlen($ciphertext);
                $iv = $this->decryptIV;

                for ($i = 0; $i < $len; ++$i) {
                    $plaintext .= $ciphertext[$i] ^ $this->encryptBlock($iv);
                    $iv = substr($iv, 1) . $ciphertext[$i];
                }

                if ($this->continuousBuffer) {
                    if ($len >= $block_size) {
                        $this->decryptIV = substr($ciphertext, -$block_size);
                    } else {
                        $this->decryptIV = substr($this->decryptIV, $len - $block_size) . substr($ciphertext, -$len);
                    }
                }
                break;
            case self::MODE_OFB8:
                $plaintext = '';
                $len = strlen($ciphertext);
                $iv = $this->decryptIV;

                for ($i = 0; $i < $len; ++$i) {
                    $xor = $this->encryptBlock($iv);
                    $plaintext .= $ciphertext[$i] ^ $xor;
                    $iv = substr($iv, 1) . $xor[0];
                }

                if ($this->continuousBuffer) {
                    $this->decryptIV = $iv;
                }
                break;
            case self::MODE_OFB:
                $xor = $this->decryptIV;
                if (strlen($buffer['xor'])) {
                    for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
                        $block = substr($ciphertext, $i, $block_size);
                        if (strlen($block) > strlen($buffer['xor'])) {
                            $xor = $this->encryptBlock($xor);
                            $buffer['xor'] .= $xor;
                        }
                        $key = Strings::shift($buffer['xor'], $block_size);
                        $plaintext .= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
                        $xor = $this->encryptBlock($xor);
                        $plaintext .= substr($ciphertext, $i, $block_size) ^ $xor;
                    }
                    $key = $xor;
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                    if ($start = strlen($ciphertext) % $block_size) {
                        $buffer['xor'] = substr($key, $start) . $buffer['xor'];
                    }
                }
                break;
            case self::MODE_STREAM:
                $plaintext = $this->decryptBlock($ciphertext);
                break;
        }
        return $this->paddable ? $this->unpad($plaintext) : $plaintext;
    }

    /**
     * Get the authentication tag
     *
     * Only used in GCM or Poly1305 mode
     *
     * @param int $length optional
     * @return string
     * @throws LengthException if $length isn't of a sufficient length
     * @throws RuntimeException if GCM mode isn't being used
     * @see self::encrypt()
     */
    public function getTag(int $length = 16)
    {
        if ($this->mode != self::MODE_GCM && !$this->usePoly1305) {
            throw new BadMethodCallException('Authentication tags are only utilized in GCM mode or with Poly1305');
        }

        if ($this->newtag === false) {
            throw new BadMethodCallException('A tag can only be returned after a round of encryption has been performed');
        }

        // the tag is 128-bits. it can't be greater than 16 bytes because that's bigger than the tag is. if it
        // were 0 you might as well be doing CTR and less than 4 provides minimal security that could be trivially
        // easily brute forced.
        // see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf#page=36
        // for more info
        if ($length < 4 || $length > 16) {
            throw new LengthException('The authentication tag must be between 4 and 16 bytes long');
        }

        return $length == 16 ?
            $this->newtag :
            substr($this->newtag, 0, $length);
    }

    /**
     * Sets the authentication tag
     *
     * Only used in GCM mode
     *
     * @throws LengthException if $length isn't of a sufficient length
     * @throws RuntimeException if GCM mode isn't being used
     * @see self::decrypt()
     */
    public function setTag(string $tag): void
    {
        if ($this->usePoly1305 && !isset($this->poly1305Key) && method_exists($this, 'createPoly1305Key')) {
            $this->createPoly1305Key();
        }

        if ($this->mode != self::MODE_GCM && !$this->usePoly1305) {
            throw new BadMethodCallException('Authentication tags are only utilized in GCM mode or with Poly1305');
        }

        $length = strlen($tag);
        if ($length < 4 || $length > 16) {
            throw new LengthException('The authentication tag must be between 4 and 16 bytes long');
        }
        $this->oldtag = $tag;
    }

    /**
     * OpenSSL CTR Processor
     *
     * PHP's OpenSSL bindings do not operate in continuous mode so we'll wrap around it. Since the keystream
     * for CTR is the same for both encrypting and decrypting this function is re-used by both SymmetricKey::encrypt()
     * and SymmetricKey::decrypt(). Also, OpenSSL doesn't implement CTR for all of it's symmetric ciphers so this
     * function will emulate CTR with ECB when necessary.
     *
     * @see self::encrypt()
     * @see self::decrypt()
     */
    private function openssl_ctr_process(string $plaintext, string &$encryptIV, array &$buffer): string
    {
        $ciphertext = '';

        $block_size = $this->block_size;
        $key = $this->key;

        if ($this->openssl_emulate_ctr) {
            $xor = $encryptIV;
            if (strlen($buffer['ciphertext'])) {
                for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
                    $block = substr($plaintext, $i, $block_size);
                    if (strlen($block) > strlen($buffer['ciphertext'])) {
                        $buffer['ciphertext'] .= openssl_encrypt($xor, $this->cipher_name_openssl_ecb, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                    }
                    Strings::increment_str($xor);
                    $otp = Strings::shift($buffer['ciphertext'], $block_size);
                    $ciphertext .= $block ^ $otp;
                }
            } else {
                for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
                    $block = substr($plaintext, $i, $block_size);
                    $otp = openssl_encrypt($xor, $this->cipher_name_openssl_ecb, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                    Strings::increment_str($xor);
                    $ciphertext .= $block ^ $otp;
                }
            }
            if ($this->continuousBuffer) {
                $encryptIV = $xor;
                if ($start = strlen($plaintext) % $block_size) {
                    $buffer['ciphertext'] = substr($key, $start) . $buffer['ciphertext'];
                }
            }

            return $ciphertext;
        }

        if (strlen($buffer['ciphertext'])) {
            $ciphertext = $plaintext ^ Strings::shift($buffer['ciphertext'], strlen($plaintext));
            $plaintext = substr($plaintext, strlen($ciphertext));

            if (!strlen($plaintext)) {
                return $ciphertext;
            }
        }

        $overflow = strlen($plaintext) % $block_size;
        if ($overflow) {
            $plaintext2 = Strings::pop($plaintext, $overflow); // ie. trim $plaintext to a multiple of $block_size and put rest of $plaintext in $plaintext2
            $encrypted = openssl_encrypt($plaintext . str_repeat("\0", $block_size), $this->cipher_name_openssl, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $encryptIV);
            $temp = Strings::pop($encrypted, $block_size);
            $ciphertext .= $encrypted . ($plaintext2 ^ $temp);
            if ($this->continuousBuffer) {
                $buffer['ciphertext'] = substr($temp, $overflow);
                $encryptIV = $temp;
            }
        } elseif (!strlen($buffer['ciphertext'])) {
            $ciphertext .= openssl_encrypt($plaintext . str_repeat("\0", $block_size), $this->cipher_name_openssl, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $encryptIV);
            $temp = Strings::pop($ciphertext, $block_size);
            if ($this->continuousBuffer) {
                $encryptIV = $temp;
            }
        }
        if ($this->continuousBuffer) {
            $encryptIV = openssl_decrypt($encryptIV, $this->cipher_name_openssl_ecb, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            if ($overflow) {
                Strings::increment_str($encryptIV);
            }
        }

        return $ciphertext;
    }

    /**
     * OpenSSL OFB Processor
     *
     * PHP's OpenSSL bindings do not operate in continuous mode so we'll wrap around it. Since the keystream
     * for OFB is the same for both encrypting and decrypting this function is re-used by both SymmetricKey::encrypt()
     * and SymmetricKey::decrypt().
     *
     * @see self::encrypt()
     * @see self::decrypt()
     */
    private function openssl_ofb_process(string $plaintext, string &$encryptIV, array &$buffer): string
    {
        if (strlen($buffer['xor'])) {
            $ciphertext = $plaintext ^ $buffer['xor'];
            $buffer['xor'] = substr($buffer['xor'], strlen($ciphertext));
            $plaintext = substr($plaintext, strlen($ciphertext));
        } else {
            $ciphertext = '';
        }

        $block_size = $this->block_size;

        $len = strlen($plaintext);
        $key = $this->key;
        $overflow = $len % $block_size;

        if (strlen($plaintext)) {
            if ($overflow) {
                $ciphertext .= openssl_encrypt(substr($plaintext, 0, -$overflow) . str_repeat("\0", $block_size), $this->cipher_name_openssl, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $encryptIV);
                $xor = Strings::pop($ciphertext, $block_size);
                if ($this->continuousBuffer) {
                    $encryptIV = $xor;
                }
                $ciphertext .= Strings::shift($xor, $overflow) ^ substr($plaintext, -$overflow);
                if ($this->continuousBuffer) {
                    $buffer['xor'] = $xor;
                }
            } else {
                $ciphertext = openssl_encrypt($plaintext, $this->cipher_name_openssl, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $encryptIV);
                if ($this->continuousBuffer) {
                    $encryptIV = substr($ciphertext, -$block_size) ^ substr($plaintext, -$block_size);
                }
            }
        }

        return $ciphertext;
    }

    /**
     * phpseclib <-> OpenSSL Mode Mapper
     *
     * May need to be overwritten by classes extending this one in some cases
     */
    protected function openssl_translate_mode(): ?string
    {
        switch ($this->mode) {
            case self::MODE_ECB:
                return 'ecb';
            case self::MODE_CBC:
                return 'cbc';
            case self::MODE_CTR:
            case self::MODE_GCM:
                return 'ctr';
            case self::MODE_CFB:
                return 'cfb';
            case self::MODE_CFB8:
                return 'cfb8';
            case self::MODE_OFB:
                return 'ofb';
        }
        return null;
    }

    /**
     * Pad "packets".
     *
     * Block ciphers working by encrypting between their specified [$this->]block_size at a time
     * If you ever need to encrypt or decrypt something that isn't of the proper length, it becomes necessary to
     * pad the input so that it is of the proper length.
     *
     * Padding is enabled by default.  Sometimes, however, it is undesirable to pad strings.  Such is the case in SSH,
     * where "packets" are padded with random bytes before being encrypted.  Unpad these packets and you risk stripping
     * away characters that shouldn't be stripped away. (SSH knows how many bytes are added because the length is
     * transmitted separately)
     *
     * @see self::disablePadding()
     */
    public function enablePadding(): void
    {
        $this->padding = true;
    }

    /**
     * Do not pad packets.
     *
     * @see self::enablePadding()
     */
    public function disablePadding(): void
    {
        $this->padding = false;
    }

    /**
     * Treat consecutive "packets" as if they are a continuous buffer.
     *
     * Say you have a 32-byte plaintext $plaintext.  Using the default behavior, the two following code snippets
     * will yield different outputs:
     *
     * <code>
     *    echo $rijndael->encrypt(substr($plaintext,  0, 16));
     *    echo $rijndael->encrypt(substr($plaintext, 16, 16));
     * </code>
     * <code>
     *    echo $rijndael->encrypt($plaintext);
     * </code>
     *
     * The solution is to enable the continuous buffer.  Although this will resolve the above discrepancy, it creates
     * another, as demonstrated with the following:
     *
     * <code>
     *    $rijndael->encrypt(substr($plaintext, 0, 16));
     *    echo $rijndael->decrypt($rijndael->encrypt(substr($plaintext, 16, 16)));
     * </code>
     * <code>
     *    echo $rijndael->decrypt($rijndael->encrypt(substr($plaintext, 16, 16)));
     * </code>
     *
     * With the continuous buffer disabled, these would yield the same output.  With it enabled, they yield different
     * outputs.  The reason is due to the fact that the initialization vector's change after every encryption /
     * decryption round when the continuous buffer is enabled.  When it's disabled, they remain constant.
     *
     * Put another way, when the continuous buffer is enabled, the state of the \phpseclib4\Crypt\*() object changes after each
     * encryption / decryption round, whereas otherwise, it'd remain constant.  For this reason, it's recommended that
     * continuous buffers not be used.  They do offer better security and are, in fact, sometimes required (SSH uses them),
     * however, they are also less intuitive and more likely to cause you problems.
     *
     * {@internal Could, but not must, extend by the child Crypt_* class}
     *
     * @see self::disableContinuousBuffer()
     */
    public function enableContinuousBuffer(): void
    {
        if ($this->mode == self::MODE_ECB) {
            return;
        }

        if ($this->mode == self::MODE_GCM) {
            throw new BadMethodCallException('This mode does not run in continuous mode');
        }

        $this->continuousBuffer = true;

        $this->setEngine();
    }

    /**
     * Treat consecutive packets as if they are a discontinuous buffer.
     *
     * The default behavior.
     *
     * {@internal Could, but not must, extend by the child Crypt_* class}
     *
     * @see self::enableContinuousBuffer()
     */
    public function disableContinuousBuffer(): void
    {
        if ($this->mode == self::MODE_ECB) {
            return;
        }
        if (!$this->continuousBuffer) {
            return;
        }

        $this->continuousBuffer = false;

        $this->setEngine();
    }

    /**
     * Test for engine validity
     *
     * @see self::__construct()
     */
    protected function isValidEngineHelper(int $engine): bool
    {
        switch ($engine) {
            case self::ENGINE_OPENSSL:
                $this->openssl_emulate_ctr = false;
                $result = $this->cipher_name_openssl &&
                          extension_loaded('openssl');
                if (!$result) {
                    return false;
                }

                $methods = openssl_get_cipher_methods();
                if (in_array($this->cipher_name_openssl, $methods)) {
                    return true;
                }
                // not all of openssl's symmetric cipher's support ctr. for those
                // that don't we'll emulate it
                switch ($this->mode) {
                    case self::MODE_CTR:
                        if (in_array($this->cipher_name_openssl_ecb, $methods)) {
                            $this->openssl_emulate_ctr = true;
                            return true;
                        }
                }
                return false;
            case self::ENGINE_EVAL:
                return method_exists($this, 'setupInlineCrypt');
            case self::ENGINE_INTERNAL:
                return true;
        }

        return false;
    }

    /**
     * Test for engine validity
     *
          * @see self::__construct()
     */
    public function isValidEngine(string $engine): bool
    {
        static $reverseMap;
        if (!isset($reverseMap)) {
            $reverseMap = array_map('strtolower', self::ENGINE_MAP);
            $reverseMap = array_flip($reverseMap);
        }
        $engine = strtolower($engine);
        if (!isset($reverseMap[$engine])) {
            return false;
        }

        return $this->isValidEngineHelper($reverseMap[$engine]);
    }

    /**
     * Sets the preferred crypt engine
     *
     * Currently, $engine could be:
     *
     * - libsodium[very fast]
     *
     * - OpenSSL  [very fast]
     *
     * - Eval     [slow]
     *
     * - PHP      [slowest]
     *
     * If the preferred crypt engine is not available the fastest available one will be used
     *
     * @see self::__construct()
     */
    public function setPreferredEngine(string $engine): void
    {
        static $reverseMap;
        if (!isset($reverseMap)) {
            $reverseMap = array_map('strtolower', self::ENGINE_MAP);
            $reverseMap = array_flip($reverseMap);
        }
        $engine = is_string($engine) ? strtolower($engine) : '';
        $this->preferredEngine = $reverseMap[$engine] ?? self::ENGINE_LIBSODIUM;

        $this->setEngine();
    }

    /**
     * Returns the engine currently being utilized
     *
     * @see self::setEngine()
     */
    public function getEngine(): string
    {
        return self::ENGINE_MAP[$this->engine];
    }

    /**
     * Sets the engine as appropriate
     *
     * @see self::__construct()
     */
    protected function setEngine(): void
    {
        $this->engine = null;

        $candidateEngines = [
            self::ENGINE_LIBSODIUM,
            self::ENGINE_OPENSSL_GCM,
            self::ENGINE_OPENSSL,
            self::ENGINE_EVAL,
        ];
        if (isset($this->preferredEngine)) {
            $temp = [$this->preferredEngine];
            $candidateEngines = array_merge(
                $temp,
                array_diff($candidateEngines, $temp)
            );
        }
        foreach ($candidateEngines as $engine) {
            if ($this->isValidEngineHelper($engine)) {
                $this->engine = $engine;
                break;
            }
        }
        if (!$this->engine) {
            $this->engine = self::ENGINE_INTERNAL;
        }

        $this->changed = $this->nonIVChanged = true;
    }

    /**
     * Encrypts a block
     *
     * Note: Must be extended by the child \phpseclib4\Crypt\* class
     */
    abstract protected function encryptBlock(string $in): string;

    /**
     * Decrypts a block
     *
     * Note: Must be extended by the child \phpseclib4\Crypt\* class
     */
    abstract protected function decryptBlock(string $in): string;

    /**
     * Setup the key (expansion)
     *
     * Only used if $engine == self::ENGINE_INTERNAL
     *
     * Note: Must extend by the child \phpseclib4\Crypt\* class
     *
     * @see self::setup()
     */
    abstract protected function setupKey();

    /**
     * Setup the self::ENGINE_INTERNAL $engine
     *
     * (re)init, if necessary, the internal cipher $engine and flush all $buffers
     * Used (only) if $engine == self::ENGINE_INTERNAL
     *
     * _setup() will be called each time if $changed === true
     * typically this happens when using one or more of following public methods:
     *
     * - setKey()
     *
     * - setIV()
     *
     * - disableContinuousBuffer()
     *
     * - First run of encrypt() / decrypt() with no init-settings
     *
     * {@internal setup() is always called before en/decryption.}
     *
     * {@internal Could, but not must, extend by the child Crypt_* class}
     *
     * @see self::setKey()
     * @see self::setIV()
     * @see self::disableContinuousBuffer()
     */
    protected function setup(): void
    {
        if (!$this->changed) {
            return;
        }

        $this->changed = false;

        if ($this->usePoly1305 && !isset($this->poly1305Key) && method_exists($this, 'createPoly1305Key')) {
            $this->createPoly1305Key();
        }

        $this->enbuffer = $this->debuffer = ['ciphertext' => '', 'xor' => '', 'pos' => 0, 'enmcrypt_init' => true];
        //$this->newtag = $this->oldtag = false;

        if ($this->usesNonce()) {
            if ($this->nonce === false) {
                throw new InsufficientSetupException('No nonce has been defined');
            }
            if ($this->mode == self::MODE_GCM && !in_array($this->engine, [self::ENGINE_LIBSODIUM, self::ENGINE_OPENSSL_GCM])) {
                $this->setupGCM();
            }
        } else {
            $this->iv = $this->origIV;
        }

        if ($this->iv === false && !in_array($this->mode, [self::MODE_STREAM, self::MODE_ECB])) {
            if ($this->mode != self::MODE_GCM || !in_array($this->engine, [self::ENGINE_LIBSODIUM, self::ENGINE_OPENSSL_GCM])) {
                throw new InsufficientSetupException('No IV has been defined');
            }
        }

        if ($this->key === false) {
            throw new InsufficientSetupException('No key has been defined');
        }

        $this->encryptIV = $this->decryptIV = $this->iv;

        switch ($this->engine) {
            case self::ENGINE_INTERNAL:
                $this->setupKey();
                break;
            case self::ENGINE_EVAL:
                if ($this->nonIVChanged) {
                    $this->setupKey();
                    $this->setupInlineCrypt();
                }
        }

        $this->nonIVChanged = false;
    }

    /**
     * Pads a string
     *
     * Pads a string using the RSA PKCS padding standards so that its length is a multiple of the blocksize.
     * $this->block_size - (strlen($text) % $this->block_size) bytes are added, each of which is equal to
     * chr($this->block_size - (strlen($text) % $this->block_size)
     *
     * If padding is disabled and $text is not a multiple of the blocksize, the string will be padded regardless
     * and padding will, hence forth, be enabled.
     *
     * @throws LengthException if padding is disabled and the plaintext's length is not a multiple of the block size
     * @see self::unpad()
     */
    protected function pad(string $text): string
    {
        $length = strlen($text);

        if (!$this->padding) {
            if ($length % $this->block_size == 0) {
                return $text;
            } else {
                throw new LengthException("The plaintext's length ($length) is not a multiple of the block size ({$this->block_size}). Try enabling padding.");
            }
        }

        $pad = $this->block_size - ($length % $this->block_size);

        return str_pad($text, $length + $pad, chr($pad));
    }

    /**
     * Unpads a string.
     *
     * If padding is enabled and the reported padding length is invalid the encryption key will be assumed to be wrong
     * and false will be returned.
     *
     * @throws LengthException if the ciphertext's length is not a multiple of the block size
     * @see self::pad()
     */
    protected function unpad(string $text): string
    {
        if (!$this->padding) {
            return $text;
        }

        $length = ord($text[-1]);

        if (!$length || $length > $this->block_size) {
            throw new BadDecryptionException("The ciphertext has an invalid padding length ($length) compared to the block size ({$this->block_size})");
        }

        return substr($text, 0, -$length);
    }

    /**
     * Setup the performance-optimized function for de/encrypt()
     *
     * Stores the created (or existing) callback function-name
     * in $this->inline_crypt
     *
     * Internally for phpseclib developers:
     *
     *     _setupInlineCrypt() would be called only if:
     *
     *     - $this->engine === self::ENGINE_EVAL
     *
     *     - each time on _setup(), after(!) _setupKey()
     *
     *
     *     This ensures that _setupInlineCrypt() has always a
     *     full ready2go initializated internal cipher $engine state
     *     where, for example, the keys already expanded,
     *     keys/block_size calculated and such.
     *
     *     It is, each time if called, the responsibility of _setupInlineCrypt():
     *
     *     - to set $this->inline_crypt to a valid and fully working callback function
     *       as a (faster) replacement for encrypt() / decrypt()
     *
     *     - NOT to create unlimited callback functions (for memory reasons!)
     *       no matter how often _setupInlineCrypt() would be called. At some
     *       point of amount they must be generic re-useable.
     *
     *     - the code of _setupInlineCrypt() it self,
     *       and the generated callback code,
     *       must be, in following order:
     *       - 100% safe
     *       - 100% compatible to encrypt()/decrypt()
     *       - using only php5+ features/lang-constructs/php-extensions if
     *         compatibility (down to php4) or fallback is provided
     *       - readable/maintainable/understandable/commented and... not-cryptic-styled-code :-)
     *       - >= 10% faster than encrypt()/decrypt() [which is, by the way,
     *         the reason for the existence of _setupInlineCrypt() :-)]
     *       - memory-nice
     *       - short (as good as possible)
     *
     * Note: - _setupInlineCrypt() is using _createInlineCryptFunction() to create the full callback function code.
     *       - In case of using inline crypting, _setupInlineCrypt() must extend by the child \phpseclib4\Crypt\* class.
     *       - The following variable names are reserved:
     *         - $_*  (all variable names prefixed with an underscore)
     *         - $self (object reference to it self. Do not use $this, but $self instead)
     *         - $in (the content of $in has to en/decrypt by the generated code)
     *       - The callback function should not use the 'return' statement, but en/decrypt'ing the content of $in only
     *
     * {@internal If a Crypt_* class providing inline crypting it must extend _setupInlineCrypt()}
     *
     * @see self::setup()
     * @see self::createInlineCryptFunction()
     * @see self::encrypt()
     * @see self::decrypt()
     */
    //protected function setupInlineCrypt();

    /**
     * Creates the performance-optimized function for en/decrypt()
     *
     * Internally for phpseclib developers:
     *
     *    _createInlineCryptFunction():
     *
     *    - merge the $cipher_code [setup'ed by _setupInlineCrypt()]
     *      with the current [$this->]mode of operation code
     *
     *    - create the $inline function, which called by encrypt() / decrypt()
     *      as its replacement to speed up the en/decryption operations.
     *
     *    - return the name of the created $inline callback function
     *
     *    - used to speed up en/decryption
     *
     *
     *
     *    The main reason why can speed up things [up to 50%] this way are:
     *
     *    - using variables more effective then regular.
     *      (ie no use of expensive arrays but integers $k_0, $k_1 ...
     *      or even, for example, the pure $key[] values hardcoded)
     *
     *    - avoiding 1000's of function calls of ie _encryptBlock()
     *      but inlining the crypt operations.
     *      in the mode of operation for() loop.
     *
     *    - full loop unroll the (sometimes key-dependent) rounds
     *      avoiding this way ++$i counters and runtime-if's etc...
     *
     *    The basic code architectur of the generated $inline en/decrypt()
     *    lambda function, in pseudo php, is:
     *
     *    <code>
     *    +----------------------------------------------------------------------------------------------+
     *    | callback $inline = create_function:                                                          |
     *    | lambda_function_0001_crypt_ECB($action, $text)                                               |
     *    | {                                                                                            |
     *    |     INSERT PHP CODE OF:                                                                      |
     *    |     $cipher_code['init_crypt'];                  // general init code.                       |
     *    |                                                  // ie: $sbox'es declarations used for       |
     *    |                                                  //     encrypt and decrypt'ing.             |
     *    |                                                                                              |
     *    |     switch ($action) {                                                                       |
     *    |         case 'encrypt':                                                                      |
     *    |             INSERT PHP CODE OF:                                                              |
     *    |             $cipher_code['init_encrypt'];       // encrypt sepcific init code.               |
     *    |                                                    ie: specified $key or $box                |
     *    |                                                        declarations for encrypt'ing.         |
     *    |                                                                                              |
     *    |             foreach ($ciphertext) {                                                          |
     *    |                 $in = $block_size of $ciphertext;                                            |
     *    |                                                                                              |
     *    |                 INSERT PHP CODE OF:                                                          |
     *    |                 $cipher_code['encrypt_block'];  // encrypt's (string) $in, which is always:  |
     *    |                                                 // strlen($in) == $this->block_size          |
     *    |                                                 // here comes the cipher algorithm in action |
     *    |                                                 // for encryption.                           |
     *    |                                                 // $cipher_code['encrypt_block'] has to      |
     *    |                                                 // encrypt the content of the $in variable   |
     *    |                                                                                              |
     *    |                 $plaintext .= $in;                                                           |
     *    |             }                                                                                |
     *    |             return $plaintext;                                                               |
     *    |                                                                                              |
     *    |         case 'decrypt':                                                                      |
     *    |             INSERT PHP CODE OF:                                                              |
     *    |             $cipher_code['init_decrypt'];       // decrypt sepcific init code                |
     *    |                                                    ie: specified $key or $box                |
     *    |                                                        declarations for decrypt'ing.         |
     *    |             foreach ($plaintext) {                                                           |
     *    |                 $in = $block_size of $plaintext;                                             |
     *    |                                                                                              |
     *    |                 INSERT PHP CODE OF:                                                          |
     *    |                 $cipher_code['decrypt_block'];  // decrypt's (string) $in, which is always   |
     *    |                                                 // strlen($in) == $this->block_size          |
     *    |                                                 // here comes the cipher algorithm in action |
     *    |                                                 // for decryption.                           |
     *    |                                                 // $cipher_code['decrypt_block'] has to      |
     *    |                                                 // decrypt the content of the $in variable   |
     *    |                 $ciphertext .= $in;                                                          |
     *    |             }                                                                                |
     *    |             return $ciphertext;                                                              |
     *    |     }                                                                                        |
     *    | }                                                                                            |
     *    +----------------------------------------------------------------------------------------------+
     *    </code>
     *
     *    See also the \phpseclib4\Crypt\*::_setupInlineCrypt()'s for
     *    productive inline $cipher_code's how they works.
     *
     *    Structure of:
     *    <code>
     *    $cipher_code = [
     *        'init_crypt'    => (string) '', // optional
     *        'init_encrypt'  => (string) '', // optional
     *        'init_decrypt'  => (string) '', // optional
     *        'encrypt_block' => (string) '', // required
     *        'decrypt_block' => (string) ''  // required
     *    ];
     *    </code>
     *
     * @see self::decrypt()
     * @see self::setupInlineCrypt()
     * @see self::encrypt()
     */
    protected function createInlineCryptFunction(array $cipher_code): \Closure
    {
        $block_size = $this->block_size;

        // optional
        $init_crypt    = $cipher_code['init_crypt']    ?? '';
        $init_encrypt  = $cipher_code['init_encrypt']  ?? '';
        $init_decrypt  = $cipher_code['init_decrypt']  ?? '';
        // required
        $encrypt_block = $cipher_code['encrypt_block'];
        $decrypt_block = $cipher_code['decrypt_block'];

        // Generating mode of operation inline code,
        // merged with the $cipher_code algorithm
        // for encrypt- and decryption.
        switch ($this->mode) {
            case self::MODE_ECB:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_plaintext_len = strlen($_text);

                    for ($_i = 0; $_i < $_plaintext_len; $_i+= ' . $block_size . ') {
                        $in = substr($_text, $_i, ' . $block_size . ');
                        ' . $encrypt_block . '
                        $_ciphertext.= $in;
                    }

                    return $_ciphertext;
                    ';

                $decrypt = $init_decrypt . '
                    $_plaintext = "";
                    $_text = str_pad($_text, strlen($_text) + (' . $block_size . ' - strlen($_text) % ' . $block_size . ') % ' . $block_size . ', chr(0));
                    $_ciphertext_len = strlen($_text);

                    for ($_i = 0; $_i < $_ciphertext_len; $_i+= ' . $block_size . ') {
                        $in = substr($_text, $_i, ' . $block_size . ');
                        ' . $decrypt_block . '
                        $_plaintext.= $in;
                    }

                    return $this->unpad($_plaintext);
                    ';
                break;
            case self::MODE_CTR:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_plaintext_len = strlen($_text);
                    $_xor = $this->encryptIV;
                    $_buffer = &$this->enbuffer;
                    if (strlen($_buffer["ciphertext"])) {
                        for ($_i = 0; $_i < $_plaintext_len; $_i+= ' . $block_size . ') {
                            $_block = substr($_text, $_i, ' . $block_size . ');
                            if (strlen($_block) > strlen($_buffer["ciphertext"])) {
                                $in = $_xor;
                                ' . $encrypt_block . '
                                \phpseclib4\Common\Functions\Strings::increment_str($_xor);
                                $_buffer["ciphertext"].= $in;
                            }
                            $_key = \phpseclib4\Common\Functions\Strings::shift($_buffer["ciphertext"], ' . $block_size . ');
                            $_ciphertext.= $_block ^ $_key;
                        }
                    } else {
                        for ($_i = 0; $_i < $_plaintext_len; $_i+= ' . $block_size . ') {
                            $_block = substr($_text, $_i, ' . $block_size . ');
                            $in = $_xor;
                            ' . $encrypt_block . '
                            \phpseclib4\Common\Functions\Strings::increment_str($_xor);
                            $_key = $in;
                            $_ciphertext.= $_block ^ $_key;
                        }
                    }
                    if ($this->continuousBuffer) {
                        $this->encryptIV = $_xor;
                        if ($_start = $_plaintext_len % ' . $block_size . ') {
                            $_buffer["ciphertext"] = substr($_key, $_start) . $_buffer["ciphertext"];
                        }
                    }

                    return $_ciphertext;
                ';

                $decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_ciphertext_len = strlen($_text);
                    $_xor = $this->decryptIV;
                    $_buffer = &$this->debuffer;

                    if (strlen($_buffer["ciphertext"])) {
                        for ($_i = 0; $_i < $_ciphertext_len; $_i+= ' . $block_size . ') {
                            $_block = substr($_text, $_i, ' . $block_size . ');
                            if (strlen($_block) > strlen($_buffer["ciphertext"])) {
                                $in = $_xor;
                                ' . $encrypt_block . '
                                \phpseclib4\Common\Functions\Strings::increment_str($_xor);
                                $_buffer["ciphertext"].= $in;
                            }
                            $_key = \phpseclib4\Common\Functions\Strings::shift($_buffer["ciphertext"], ' . $block_size . ');
                            $_plaintext.= $_block ^ $_key;
                        }
                    } else {
                        for ($_i = 0; $_i < $_ciphertext_len; $_i+= ' . $block_size . ') {
                            $_block = substr($_text, $_i, ' . $block_size . ');
                            $in = $_xor;
                            ' . $encrypt_block . '
                            \phpseclib4\Common\Functions\Strings::increment_str($_xor);
                            $_key = $in;
                            $_plaintext.= $_block ^ $_key;
                        }
                    }
                    if ($this->continuousBuffer) {
                        $this->decryptIV = $_xor;
                        if ($_start = $_ciphertext_len % ' . $block_size . ') {
                            $_buffer["ciphertext"] = substr($_key, $_start) . $_buffer["ciphertext"];
                        }
                    }

                    return $_plaintext;
                    ';
                break;
            case self::MODE_CFB:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_buffer = &$this->enbuffer;

                    if ($this->continuousBuffer) {
                        $_iv = &$this->encryptIV;
                        $_pos = &$_buffer["pos"];
                    } else {
                        $_iv = $this->encryptIV;
                        $_pos = 0;
                    }
                    $_len = strlen($_text);
                    $_i = 0;
                    if ($_pos) {
                        $_orig_pos = $_pos;
                        $_max = ' . $block_size . ' - $_pos;
                        if ($_len >= $_max) {
                            $_i = $_max;
                            $_len-= $_max;
                            $_pos = 0;
                        } else {
                            $_i = $_len;
                            $_pos+= $_len;
                            $_len = 0;
                        }
                        $_ciphertext = substr($_iv, $_orig_pos) ^ $_text;
                        $_iv = substr_replace($_iv, $_ciphertext, $_orig_pos, $_i);
                    }
                    while ($_len >= ' . $block_size . ') {
                        $in = $_iv;
                        ' . $encrypt_block . ';
                        $_iv = $in ^ substr($_text, $_i, ' . $block_size . ');
                        $_ciphertext.= $_iv;
                        $_len-= ' . $block_size . ';
                        $_i+= ' . $block_size . ';
                    }
                    if ($_len) {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_iv = $in;
                        $_block = $_iv ^ substr($_text, $_i);
                        $_iv = substr_replace($_iv, $_block, 0, $_len);
                        $_ciphertext.= $_block;
                        $_pos = $_len;
                    }
                    return $_ciphertext;
                ';

                $decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_buffer = &$this->debuffer;

                    if ($this->continuousBuffer) {
                        $_iv = &$this->decryptIV;
                        $_pos = &$_buffer["pos"];
                    } else {
                        $_iv = $this->decryptIV;
                        $_pos = 0;
                    }
                    $_len = strlen($_text);
                    $_i = 0;
                    if ($_pos) {
                        $_orig_pos = $_pos;
                        $_max = ' . $block_size . ' - $_pos;
                        if ($_len >= $_max) {
                            $_i = $_max;
                            $_len-= $_max;
                            $_pos = 0;
                        } else {
                            $_i = $_len;
                            $_pos+= $_len;
                            $_len = 0;
                        }
                        $_plaintext = substr($_iv, $_orig_pos) ^ $_text;
                        $_iv = substr_replace($_iv, substr($_text, 0, $_i), $_orig_pos, $_i);
                    }
                    while ($_len >= ' . $block_size . ') {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_iv = $in;
                        $cb = substr($_text, $_i, ' . $block_size . ');
                        $_plaintext.= $_iv ^ $cb;
                        $_iv = $cb;
                        $_len-= ' . $block_size . ';
                        $_i+= ' . $block_size . ';
                    }
                    if ($_len) {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_iv = $in;
                        $_plaintext.= $_iv ^ substr($_text, $_i);
                        $_iv = substr_replace($_iv, substr($_text, $_i), 0, $_len);
                        $_pos = $_len;
                    }

                    return $_plaintext;
                    ';
                break;
            case self::MODE_CFB8:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_len = strlen($_text);
                    $_iv = $this->encryptIV;

                    for ($_i = 0; $_i < $_len; ++$_i) {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_ciphertext .= ($_c = $_text[$_i] ^ $in);
                        $_iv = substr($_iv, 1) . $_c;
                    }

                    if ($this->continuousBuffer) {
                        if ($_len >= ' . $block_size . ') {
                            $this->encryptIV = substr($_ciphertext, -' . $block_size . ');
                        } else {
                            $this->encryptIV = substr($this->encryptIV, $_len - ' . $block_size . ') . substr($_ciphertext, -$_len);
                        }
                    }

                    return $_ciphertext;
                    ';
                $decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_len = strlen($_text);
                    $_iv = $this->decryptIV;

                    for ($_i = 0; $_i < $_len; ++$_i) {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_plaintext .= $_text[$_i] ^ $in;
                        $_iv = substr($_iv, 1) . $_text[$_i];
                    }

                    if ($this->continuousBuffer) {
                        if ($_len >= ' . $block_size . ') {
                            $this->decryptIV = substr($_text, -' . $block_size . ');
                        } else {
                            $this->decryptIV = substr($this->decryptIV, $_len - ' . $block_size . ') . substr($_text, -$_len);
                        }
                    }

                    return $_plaintext;
                    ';
                break;
            case self::MODE_OFB8:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_len = strlen($_text);
                    $_iv = $this->encryptIV;

                    for ($_i = 0; $_i < $_len; ++$_i) {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_ciphertext.= $_text[$_i] ^ $in;
                        $_iv = substr($_iv, 1) . $in[0];
                    }

                    if ($this->continuousBuffer) {
                        $this->encryptIV = $_iv;
                    }

                    return $_ciphertext;
                    ';
                $decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_len = strlen($_text);
                    $_iv = $this->decryptIV;

                    for ($_i = 0; $_i < $_len; ++$_i) {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_plaintext.= $_text[$_i] ^ $in;
                        $_iv = substr($_iv, 1) . $in[0];
                    }

                    if ($this->continuousBuffer) {
                        $this->decryptIV = $_iv;
                    }

                    return $_plaintext;
                    ';
                break;
            case self::MODE_OFB:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_plaintext_len = strlen($_text);
                    $_xor = $this->encryptIV;
                    $_buffer = &$this->enbuffer;

                    if (strlen($_buffer["xor"])) {
                        for ($_i = 0; $_i < $_plaintext_len; $_i+= ' . $block_size . ') {
                            $_block = substr($_text, $_i, ' . $block_size . ');
                            if (strlen($_block) > strlen($_buffer["xor"])) {
                                $in = $_xor;
                                ' . $encrypt_block . '
                                $_xor = $in;
                                $_buffer["xor"].= $_xor;
                            }
                            $_key = \phpseclib4\Common\Functions\Strings::shift($_buffer["xor"], ' . $block_size . ');
                            $_ciphertext.= $_block ^ $_key;
                        }
                    } else {
                        for ($_i = 0; $_i < $_plaintext_len; $_i+= ' . $block_size . ') {
                            $in = $_xor;
                            ' . $encrypt_block . '
                            $_xor = $in;
                            $_ciphertext.= substr($_text, $_i, ' . $block_size . ') ^ $_xor;
                        }
                        $_key = $_xor;
                    }
                    if ($this->continuousBuffer) {
                        $this->encryptIV = $_xor;
                        if ($_start = $_plaintext_len % ' . $block_size . ') {
                             $_buffer["xor"] = substr($_key, $_start) . $_buffer["xor"];
                        }
                    }
                    return $_ciphertext;
                    ';

                $decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_ciphertext_len = strlen($_text);
                    $_xor = $this->decryptIV;
                    $_buffer = &$this->debuffer;

                    if (strlen($_buffer["xor"])) {
                        for ($_i = 0; $_i < $_ciphertext_len; $_i+= ' . $block_size . ') {
                            $_block = substr($_text, $_i, ' . $block_size . ');
                            if (strlen($_block) > strlen($_buffer["xor"])) {
                                $in = $_xor;
                                ' . $encrypt_block . '
                                $_xor = $in;
                                $_buffer["xor"].= $_xor;
                            }
                            $_key = \phpseclib4\Common\Functions\Strings::shift($_buffer["xor"], ' . $block_size . ');
                            $_plaintext.= $_block ^ $_key;
                        }
                    } else {
                        for ($_i = 0; $_i < $_ciphertext_len; $_i+= ' . $block_size . ') {
                            $in = $_xor;
                            ' . $encrypt_block . '
                            $_xor = $in;
                            $_plaintext.= substr($_text, $_i, ' . $block_size . ') ^ $_xor;
                        }
                        $_key = $_xor;
                    }
                    if ($this->continuousBuffer) {
                        $this->decryptIV = $_xor;
                        if ($_start = $_ciphertext_len % ' . $block_size . ') {
                             $_buffer["xor"] = substr($_key, $_start) . $_buffer["xor"];
                        }
                    }
                    return $_plaintext;
                    ';
                break;
            case self::MODE_STREAM:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    ' . $encrypt_block . '
                    return $_ciphertext;
                    ';
                $decrypt = $init_decrypt . '
                    $_plaintext = "";
                    ' . $decrypt_block . '
                    return $_plaintext;
                    ';
                break;
            // case self::MODE_CBC:
            default:
                $encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_plaintext_len = strlen($_text);

                    $in = $this->encryptIV;

                    for ($_i = 0; $_i < $_plaintext_len; $_i+= ' . $block_size . ') {
                        $in = substr($_text, $_i, ' . $block_size . ') ^ $in;
                        ' . $encrypt_block . '
                        $_ciphertext.= $in;
                    }

                    if ($this->continuousBuffer) {
                        $this->encryptIV = $in;
                    }

                    return $_ciphertext;
                    ';

                $decrypt = $init_decrypt . '
                    $_plaintext = "";
                    $_text = str_pad($_text, strlen($_text) + (' . $block_size . ' - strlen($_text) % ' . $block_size . ') % ' . $block_size . ', chr(0));
                    $_ciphertext_len = strlen($_text);

                    $_iv = $this->decryptIV;

                    for ($_i = 0; $_i < $_ciphertext_len; $_i+= ' . $block_size . ') {
                        $in = $_block = substr($_text, $_i, ' . $block_size . ');
                        ' . $decrypt_block . '
                        $_plaintext.= $in ^ $_iv;
                        $_iv = $_block;
                    }

                    if ($this->continuousBuffer) {
                        $this->decryptIV = $_iv;
                    }

                    return $this->unpad($_plaintext);
                    ';
                break;
        }

        // Before discrediting this, please read the following:
        // @see https://github.com/phpseclib/phpseclib/issues/1293
        // @see https://github.com/phpseclib/phpseclib/pull/1143

        /** @var \Closure $func */
        $func = eval(<<<PHP
            return function (string \$_action, string \$_text): string
            {
                {$init_crypt}
                if (\$_action === 'encrypt') {
                    {$encrypt}
                } else {
                    {$decrypt}
                }
            };
            PHP
        );

        $bindedClosure = \Closure::bind($func, $this, static::class);
        if ($bindedClosure instanceof \Closure) {
            return $bindedClosure;
        }
        throw new LogicException('\Closure::bind() failed.');
    }

    /**
     * Sets up GCM parameters
     *
     * See steps 1-2 of https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf#page=23
     * for more info
     */
    private function setupGCM(): void
    {
        // don't keep on re-calculating $this->h
        if (!$this->h || $this->hKey != $this->key) {
            $cipher = new static('ecb');
            $cipher->setKey($this->key);
            $cipher->disablePadding();

            $this->h = self::$gcmField->newInteger(
                Strings::switchEndianness($cipher->encrypt("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"))
            );
            $this->hKey = $this->key;
        }

        if (strlen($this->nonce) == 12) {
            $this->iv = $this->nonce . "\0\0\0\1";
        } else {
            $this->iv = $this->ghash(
                self::nullPad128($this->nonce) . str_repeat("\0", 8) . self::len64($this->nonce)
            );
        }
    }

    /**
     * Performs GHASH operation
     *
     * See https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf#page=20
     * for more info
     *
     * @see self::decrypt()
          * @see self::encrypt()
     */
    private function ghash(string $x): string
    {
        $h = $this->h;
        $y = ["\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"];
        $x = str_split($x, 16);
        $n = 0;
        // the switchEndianness calls are necessary because the multiplication algorithm in BinaryField/Integer
        // interprets strings as polynomials in big endian order whereas in GCM they're interpreted in little
        // endian order per https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf#page=19.
        // big endian order is what binary field elliptic curves use per http://www.secg.org/sec1-v2.pdf#page=18.

        // we could switchEndianness here instead of in the while loop but doing so in the while loop seems like it
        // might be slightly more performant
        //$x = Strings::switchEndianness($x);
        foreach ($x as $xn) {
            $xn = Strings::switchEndianness($xn);
            $t = $y[$n] ^ $xn;
            $temp = self::$gcmField->newInteger($t);
            $y[++$n] = $temp->multiply($h)->toBytes();
            $y[$n] = substr($y[$n], 1);
        }
        $y[$n] = Strings::switchEndianness($y[$n]);
        return $y[$n];
    }

    /**
     * Returns the bit length of a string in a packed format
     *
     * @see self::setupGCM()
     * @see self::decrypt()
          * @see self::encrypt()
     */
    private static function len64(string $str): string
    {
        return "\0\0\0\0" . pack('N', 8 * strlen($str));
    }

    /**
     * NULL pads a string to be a multiple of 128
     *
     * @see self::setupGCM()
     * @see self::decrypt()
          * @see self::encrypt()
     */
    protected static function nullPad128(string $str): string
    {
        $len = strlen($str);
        return $str . str_repeat("\0", 16 * ((int) ceil($len / 16)) - $len);
    }

    /**
     * Calculates Poly1305 MAC
     *
     * On my system ChaCha20, with libsodium, takes 0.5s. With this custom Poly1305 implementation
     * it takes 1.2s.
     *
     *@see self::decrypt()
          * @see self::encrypt()
     */
    protected function poly1305(string $text): string
    {
        $s = $this->poly1305Key; // strlen($this->poly1305Key) == 32
        $r = Strings::shift($s, 16);
        $r = strrev($r);
        $r &= "\x0f\xff\xff\xfc\x0f\xff\xff\xfc\x0f\xff\xff\xfc\x0f\xff\xff\xff";
        $s = strrev($s);

        $r = self::$poly1305Field->newInteger(new BigInteger($r, 256));
        $s = self::$poly1305Field->newInteger(new BigInteger($s, 256));
        $a = self::$poly1305Field->newInteger(new BigInteger());

        $blocks = str_split($text, 16);
        foreach ($blocks as $block) {
            $n = strrev($block . chr(1));
            $n = self::$poly1305Field->newInteger(new BigInteger($n, 256));
            $a = $a->add($n);
            $a = $a->multiply($r);
        }
        $r = $a->toBigInteger()->add($s->toBigInteger());
        $mask = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
        return strrev($r->toBytes()) & $mask;
    }

    /**
     * Return the mode
     *
     * You can do $obj instanceof AES or whatever to get the cipher but you can't do that to get the mode
     */
    public function getMode(): string
    {
        return array_flip(self::MODE_MAP)[$this->mode];
    }

    /**
     * Is the continuous buffer enabled?
     */
    public function continuousBufferEnabled(): bool
    {
        return $this->continuousBuffer;
    }

    public function setMetaData(string $key, mixed $value): void
    {
        $this->metadata[$key] = $value;
    }

    public function getMetaData(string $key): mixed
    {
        return $this->metadata[$key];
    }

    public function hasMetaData(string $key): bool
    {
        return isset($this->metadata[$key]);
    }

    public function deleteMetaData(string $key): void
    {
        unset($this->metadata[$key]);
    }
}
