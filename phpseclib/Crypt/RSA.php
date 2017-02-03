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
 * extract(\phpseclib\Crypt\RSA::createKey());
 *
 * $plaintext = 'terrafrost';
 *
 * $ciphertext = $publickey->encrypt($plaintext);
 *
 * echo $privatekey->decrypt($ciphertext);
 * ?>
 * </code>
 *
 * Here's an example of how to create signatures and verify signatures with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * extract(\phpseclib\Crypt\RSA::createKey());
 *
 * $plaintext = 'terrafrost';
 *
 * $signature = $privatekey->sign($plaintext);
 *
 * echo $publickey->verify($plaintext, $signature) ? 'verified' : 'unverified';
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   RSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt;

use ParagonIE\ConstantTime\Base64;
use phpseclib\File\ASN1;
use phpseclib\Math\BigInteger;
use phpseclib\Common\Functions\Strings;
use phpseclib\File\ASN1\Maps\DigestInfo;

/**
 * Pure-PHP PKCS#1 compliant implementation of RSA.
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class RSA
{
    /**#@+
     * @access public
     * @see self::encrypt()
     * @see self::decrypt()
     */
    /**
     * Use {@link http://en.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding Optimal Asymmetric Encryption Padding}
     * (OAEP) for encryption / decryption.
     *
     * Uses sha256 by default
     *
     * @see self::setHash()
     * @see self::setMGFHash()
     */
    const PADDING_OAEP = 1;
    /**
     * Use PKCS#1 padding.
     *
     * Although self::PADDING_OAEP / self::PADDING_PSS  offers more security, including PKCS#1 padding is necessary for purposes of backwards
     * compatibility with protocols (like SSH-1) written before OAEP's introduction.
     */
    const PADDING_PKCS1 = 2;
    /**
     * Do not use any padding
     *
     * Although this method is not recommended it can none-the-less sometimes be useful if you're trying to decrypt some legacy
     * stuff, if you're trying to diagnose why an encrypted message isn't decrypting, etc.
     */
    const PADDING_NONE = 3;
    /**
     * Use PKCS#1 padding with PKCS1 v1.5 compatibility
     *
     * A PKCS1 v2.1 encrypted message may not successfully decrypt with a PKCS1 v1.5 implementation (such as OpenSSL).
     */
    const PADDING_PKCS15_COMPAT = 6;
    /**#@-*/

    /**#@+
     * @access public
     * @see self::sign()
     * @see self::verify()
     * @see self::setHash()
     */
    /**
     * Use the Probabilistic Signature Scheme for signing
     *
     * Uses sha256 and 0 as the salt length
     *
     * @see self::setSaltLength()
     * @see self::setMGFHash()
     * @see self::setHash()
     */
    const PADDING_PSS = 4;
    /**
     * Use a relaxed version of PKCS#1 padding for signature verification
     */
    const PADDING_RELAXED_PKCS1 = 5;
    /**#@-*/

    /**#@+
     * @access private
     * @see self::__construct()
     */
    /**
     * To use the pure-PHP implementation
     */
    const ENGINE_INTERNAL = 1;
    /**
     * To use the OpenSSL library
     *
     * (if enabled; otherwise, the internal implementation will be used)
     */
    const ENGINE_OPENSSL = 2;
    /**#@-*/

    /**
     * Precomputed Zero
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    private static $zero;

    /**
     * Precomputed One
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    private static $one;

    /**
     * Private Key Format
     *
     * @var string
     * @access private
     */
    private $privateKeyFormat = 'PKCS8';

    /**
     * Public Key Format
     *
     * @var string
     * @access private
     */
    private $publicKeyFormat = 'PKCS8';

    /**
     * Modulus (ie. n)
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    private $modulus;

    /**
     * Modulus length
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    private $k;

    /**
     * Exponent (ie. e or d)
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    private $exponent;

    /**
     * Primes for Chinese Remainder Theorem (ie. p and q)
     *
     * @var array
     * @access private
     */
    private $primes;

    /**
     * Exponents for Chinese Remainder Theorem (ie. dP and dQ)
     *
     * @var array
     * @access private
     */
    private $exponents;

    /**
     * Coefficients for Chinese Remainder Theorem (ie. qInv)
     *
     * @var array
     * @access private
     */
    private $coefficients;

    /**
     * Hash name
     *
     * @var string
     * @access private
     */
    private $hashName;

    /**
     * Hash function
     *
     * @var \phpseclib\Crypt\Hash
     * @access private
     */
    private $hash;

    /**
     * Length of hash function output
     *
     * @var int
     * @access private
     */
    private $hLen;

    /**
     * Length of salt
     *
     * @var int
     * @access private
     */
    private $sLen;

    /**
     * Hash function for the Mask Generation Function
     *
     * @var \phpseclib\Crypt\Hash
     * @access private
     */
    private $mgfHash;

    /**
     * Length of MGF hash function output
     *
     * @var int
     * @access private
     */
    private $mgfHLen;

    /**
     * Public Exponent
     *
     * @var mixed
     * @access private
     */
    private $publicExponent = false;

    /**
     * Password
     *
     * @var string
     * @access private
     */
    private $password = false;

    /**
     * Loaded File Format
     *
     * @var string
     * @access private
     */
    private $format = false;

    /**
     * OpenSSL configuration file name.
     *
     * Set to null to use system configuration file.
     *
     * @see self::createKey()
     * @var mixed
     * @access public
     */
    private static $configFile;

    /**
     * Supported file formats (lower case)
     *
     * @see self::initialize_static_variables()
     * @var array
     * @access private
     */
    private static $fileFormats = false;

    /**
     * Supported file formats (original case)
     *
     * @see self::initialize_static_variables()
     * @var array
     * @access private
     */
    private static $origFileFormats = false;

    /**
     * Public exponent
     *
     * @var int
     * @link http://en.wikipedia.org/wiki/65537_%28number%29
     * @access private
     */
    private static $defaultExponent = 65537;

    /**
     * Smallest Prime
     *
     * Per <http://cseweb.ucsd.edu/~hovav/dist/survey.pdf#page=5>, this number ought not result in primes smaller
     * than 256 bits. As a consequence if the key you're trying to create is 1024 bits and you've set smallestPrime
     * to 384 bits then you're going to get a 384 bit prime and a 640 bit prime (384 + 1024 % 384). At least if
     * engine is set to self::ENGINE_INTERNAL. If Engine is set to self::ENGINE_OPENSSL then smallest Prime is
     * ignored (ie. multi-prime RSA support is more intended as a way to speed up RSA key generation when there's
     * a chance neither gmp nor OpenSSL are installed)
     *
     * @var int
     * @access private
     */
    private static $smallestPrime = 4096;

    /**
     * Engine
     *
     * This is only used for key generation. Valid values are RSA::ENGINE_INTERNAL and RSA::ENGINE_OPENSSL
     *
     * @var int
     * @access private
     */
    private static $engine = NULL;

    /**
     * Initialize static variables
     *
     * @access private
     */
    private static function initialize_static_variables()
    {
        if (!isset(self::$zero)) {
            self::$zero= new BigInteger(0);
            self::$one = new BigInteger(1);
            self::$configFile = __DIR__ . '/../openssl.cnf';

            if (self::$fileFormats === false) {
                self::$fileFormats = [];
                foreach (glob(__DIR__ . '/RSA/*.php') as $file) {
                    $name = pathinfo($file, PATHINFO_FILENAME);
                    $type = 'phpseclib\Crypt\RSA\\' . $name;
                    self::$fileFormats[strtolower($name)] = $type;
                    self::$origFileFormats[] = $name;
                }
            }
        }
    }

    /**
     * The constructor
     *
     * If you want to make use of the openssl extension, you'll need to set the mode manually, yourself.  The reason
     * \phpseclib\Crypt\RSA doesn't do it is because OpenSSL doesn't fail gracefully.  openssl_pkey_new(), in particular, requires
     * openssl.cnf be present somewhere and, unfortunately, the only real way to find out is too late.
     *
     * @return \phpseclib\Crypt\RSA
     * @access public
     */
    public function __construct()
    {
        self::initialize_static_variables();

        $this->hash = new Hash('sha256');
        $this->hLen = $this->hash->getLengthInBytes();
        $this->hashName = 'sha256';
        $this->mgfHash = new Hash('sha256');
        $this->mgfHLen = $this->mgfHash->getLengthInBytes();
    }

    /**
     * Sets the public exponent
     *
     * This will be 65537 unless changed.
     *
     * @access public
     * @param int $val
     */
    public static function setExponent($val)
    {
        self::$defaultExponent = $val;
    }

    /**
     * Sets the smallest prime number in bits
     *
     * This will be 4096 unless changed.
     *
     * @access public
     * @param int $val
     */
    public static function setSmallestPrime($val)
    {
        self::$smallestPrime = $val;
    }

    /**
     * Tests engine validity
     *
     * @access public
     * @param int $val
     */
    public static function isValidEngine($val)
    {
        switch ($val) {
            case self::ENGINE_OPENSSL:
                return extension_loaded('openssl') && file_exists(self::$configFile);
            case self::ENGINE_INTERNAL:
                return true;
        }

        return false;
    }

    /**
     * Sets the engine
     *
     * Only used in RSA::createKey. Valid values are RSA::ENGINE_OPENSSL and RSA::ENGINE_INTERNAL
     *
     * @access public
     * @param int $val
     */
    public static function setPreferredEngine($val)
    {
        self::$engine = null;
        $candidateEngines = [
            $val,
            self::ENGINE_OPENSSL
        ];
        foreach ($candidateEngines as $engine) {
            if (self::isValidEngine($engine)) {
                self::$engine = $engine;
                break;
            }
        }
        if (!isset(self::$engine)) {
            self::$engine = self::ENGINE_INTERNAL;
        }
    }

    /**
     * Returns the engine
     *
     * @access public
     * @return int
     */
    public static function getEngine($val)
    {
        return self::$engine;
    }

    /**
     * Create public / private key pair
     *
     * Returns an array with the following three elements:
     *  - 'privatekey': The private key.
     *  - 'publickey':  The public key.
     *  - 'partialkey': A partially computed key (if the execution time exceeded $timeout).
     *                  Will need to be passed back to \phpseclib\Crypt\RSA::createKey() as the third parameter for further processing.
     *
     * @access public
     * @param int $bits
     * @param int $timeout
     * @param array $p
     */
    public static function createKey($bits = 2048)
    {
        self::initialize_static_variables();

        if (!isset(self::$engine)) {
            self::setPreferredEngine(self::ENGINE_OPENSSL);
        }

        // OpenSSL uses 65537 as the exponent and requires RSA keys be 384 bits minimum

        if (self::$engine == self::ENGINE_OPENSSL && $bits >= 384 && self::$defaultExponent == 65537) {
            $config = [];
            if (isset(self::$configFile)) {
                $config['config'] = self::$configFile;
            }
            $rsa = openssl_pkey_new(['private_key_bits' => $bits] + $config);
            openssl_pkey_export($rsa, $privatekeystr, null, $config);
            $privatekey = new RSA();
            $privatekey->load($privatekeystr);

            $publickeyarr = openssl_pkey_get_details($rsa);
            $publickey = new RSA();
            $publickey->load($publickeyarr['key']);

            // clear the buffer of error strings stemming from a minimalistic openssl.cnf
            while (openssl_error_string() !== false) {
            }

            return [
                'privatekey' => $privatekey,
                'publickey' => $publickey,
                'partialkey' => false
            ];
        }

        static $e;
        if (!isset($e)) {
            $e = new BigInteger(self::$defaultExponent);
        }

        $regSize = $bits >> 1; // divide by two to see how many bits P and Q would be
        if ($regSize > self::$smallestPrime) {
            $num_primes = floor($bits / self::$smallestPrime);
            $regSize = self::$smallestPrime;
        } else {
            $num_primes = 2;
        }

        $n = clone self::$one;
        $exponents = $coefficients = $primes = [];
        $lcm = [
            'top' => clone self::$one,
            'bottom' => false
        ];

        do {
            for ($i = 1; $i <= $num_primes; $i++) {
                if ($i != $num_primes) {
                    $primes[$i] = BigInteger::randomPrime($regSize);
                } else {
                    extract(BigInteger::minMaxBits($bits));
                    list($min) = $min->divide($n);
                    $min = $min->add(self::$one);
                    list($max) = $max->divide($n);
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

            list($temp) = $lcm['top']->divide($lcm['bottom']);
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
        $privatekey = new RSA();
        $privatekey->modulus = $n;
        $privatekey->k = $bits >> 3;
        $privatekey->publicExponent = $e;
        $privatekey->exponent = $d;
        $privatekey->privateExponent = $e;
        $privatekey->primes = $primes;
        $privatekey->exponents = $exponents;
        $privatekey->coefficients = $coefficients;

        $publickey = new RSA();
        $publickey->modulus = $n;
        $publickey->k = $bits >> 3;
        $publickey->exponent = $e;

        return [
            'privatekey' => $privatekey,
            'publickey'  => $publickey
        ];
    }

    /**
     * Add a fileformat plugin
     *
     * The plugin needs to either already be loaded or be auto-loadable.
     * Loading a plugin whose shortname overwrite an existing shortname will overwrite the old plugin.
     *
     * @see self::load()
     * @param string $fullname
     * @access public
     * @return bool
     */
    public static function addFileFormat($fullname)
    {
        self::initialize_static_variables();

        if (class_exists($fullname)) {
            $meta = new \ReflectionClass($path);
            $shortname = $meta->getShortName();
            self::$fileFormats[strtolower($shortname)] = $fullname;
            self::$origFileFormats[] = $shortname;
        }
    }

    /**
     * Returns a list of supported formats.
     *
     * @access public
     * @return array
     */
    public static function getSupportedFormats()
    {
        self::initialize_static_variables();

        return self::$origFileFormats;
    }

    /**
     * Loads a public or private key
     *
     * Returns true on success and false on failure (ie. an incorrect password was provided or the key was malformed)
     *
     * @access public
     * @param string $key
     * @param int $type optional
     */
    public function load($key, $type = false)
    {
        if ($key instanceof RSA) {
            $this->privateKeyFormat = $key->privateKeyFormat;
            $this->publicKeyFormat = $key->publicKeyFormat;
            $this->k = $key->k;
            $this->hLen = $key->hLen;
            $this->sLen = $key->sLen;
            $this->mgfHLen = $key->mgfHLen;
            $this->password = $key->password;

            if (is_object($key->hash)) {
                $this->hash = new Hash($key->hash->getHash());
            }
            if (is_object($key->mgfHash)) {
                $this->mgfHash = new Hash($key->mgfHash->getHash());
            }

            if (is_object($key->modulus)) {
                $this->modulus = clone $key->modulus;
            }
            if (is_object($key->exponent)) {
                $this->exponent = clone $key->exponent;
            }
            if (is_object($key->publicExponent)) {
                $this->publicExponent = clone $key->publicExponent;
            }

            $this->primes = [];
            $this->exponents = [];
            $this->coefficients = [];

            foreach ($this->primes as $prime) {
                $this->primes[] = clone $prime;
            }
            foreach ($this->exponents as $exponent) {
                $this->exponents[] = clone $exponent;
            }
            foreach ($this->coefficients as $coefficient) {
                $this->coefficients[] = clone $coefficient;
            }

            return true;
        }

        $components = false;
        if ($type === false) {
            foreach (self::$fileFormats as $format) {
                try {
                    $components = $format::load($key, $this->password);
                } catch (\Exception $e) {
                    $components = false;
                }
                if ($components !== false) {
                    break;
                }
            }
        } else {
            $format = strtolower($type);
            if (isset(self::$fileFormats[$format])) {
                $format = self::$fileFormats[$format];
                $components = $format::load($key, $this->password);
            }
        }

        if ($components === false) {
            $this->format = false;
            return false;
        }

        $this->format = $format;

        $this->modulus = $components['modulus'];
        $this->k = $this->modulus->getLengthInBytes();
        $this->exponent = isset($components['privateExponent']) ? $components['privateExponent'] : $components['publicExponent'];
        if (isset($components['primes'])) {
            $this->primes = $components['primes'];
            $this->exponents = $components['exponents'];
            $this->coefficients = $components['coefficients'];
            $this->publicExponent = $components['publicExponent'];
        } else {
            $this->primes = [];
            $this->exponents = [];
            $this->coefficients = [];
            $this->publicExponent = false;
        }

        if ($components['isPublicKey']) {
            $this->setPublicKey();
        }

        return true;
    }

    /**
     * Returns the format of the loaded key.
     *
     * If the key that was loaded wasn't in a valid or if the key was auto-generated
     * with RSA::createKey() then this will return false.
     *
     * @see self::load()
     * @access public
     * @return mixed
     */
    public function getLoadedFormat()
    {
        if ($this->format === false) {
            return false;
        }

        $meta = new \ReflectionClass($this->format);
        return $meta->getShortName();
    }

    /**
     * Returns the private key
     *
     * The private key is only returned if the currently loaded key contains the constituent prime numbers.
     *
     * @see self::getPublicKey()
     * @access public
     * @param string $type optional
     * @return mixed
     */
    public function getPrivateKey($type = 'PKCS1')
    {
        $type = strtolower($type);
        if (!isset(self::$fileFormats[$type])) {
            return false;
        }
        $type = self::$fileFormats[$type];
        if (!method_exists($type, 'savePrivateKey')) {
            return false;
        }

        if (empty($this->primes)) {
            return false;
        }

        return $type::savePrivateKey($this->modulus, $this->publicExponent, $this->exponent, $this->primes, $this->exponents, $this->coefficients, $this->password);

        /*
        $key = $type::savePrivateKey($this->modulus, $this->publicExponent, $this->exponent, $this->primes, $this->exponents, $this->coefficients, $this->password);
        if ($key !== false || count($this->primes) == 2) {
            return $key;
        }

        $nSize = $this->getSize() >> 1;

        $primes = [1 => clone self::$one, clone self::$one];
        $i = 1;
        foreach ($this->primes as $prime) {
            $primes[$i] = $primes[$i]->multiply($prime);
            if ($primes[$i]->getLength() >= $nSize) {
                $i++;
            }
        }

        $exponents = [];
        $coefficients = [2 => $primes[2]->modInverse($primes[1])];

        foreach ($primes as $i => $prime) {
            $temp = $prime->subtract(self::$one);
            $exponents[$i] = $this->modulus->modInverse($temp);
        }

        return $type::savePrivateKey($this->modulus, $this->publicExponent, $this->exponent, $primes, $exponents, $coefficients, $this->password);
        */
    }

    /**
     * Returns the key size
     *
     * More specifically, this returns the size of the modulo in bits.
     *
     * @access public
     * @return int
     */
    public function getLength()
    {
        return !isset($this->modulus) ? 0 : $this->modulus->getLength();
    }

    /**
     * Sets the password
     *
     * Private keys can be encrypted with a password.  To unset the password, pass in the empty string or false.
     * Or rather, pass in $password such that empty($password) && !is_string($password) is true.
     *
     * @see self::createKey()
     * @see self::load()
     * @access public
     * @param string $password
     */
    public function setPassword($password = false)
    {
        $this->password = $password;
    }

    /**
     * Defines the public key
     *
     * Some private key formats define the public exponent and some don't.  Those that don't define it are problematic when
     * used in certain contexts.  For example, in SSH-2, RSA authentication works by sending the public key along with a
     * message signed by the private key to the server.  The SSH-2 server looks the public key up in an index of public keys
     * and if it's present then proceeds to verify the signature.  Problem is, if your private key doesn't include the public
     * exponent this won't work unless you manually add the public exponent. phpseclib tries to guess if the key being used
     * is the public key but in the event that it guesses incorrectly you might still want to explicitly set the key as being
     * public.
     *
     * Do note that when a new key is loaded the index will be cleared.
     *
     * Returns true on success, false on failure
     *
     * @see self::getPublicKey()
     * @access public
     * @param string $key optional
     * @param int $type optional
     * @return bool
     */
    public function setPublicKey($key = false, $type = false)
    {
        // if a public key has already been loaded return false
        if (!empty($this->publicExponent)) {
            return false;
        }

        if ($key === false && !empty($this->modulus)) {
            $this->publicExponent = $this->exponent;
            return true;
        }

        $components = false;
        if ($type === false) {
            foreach (self::$fileFormats as $format) {
                if (!method_exists($format, 'savePublicKey')) {
                    continue;
                }
                try {
                    $components = $format::load($key, $this->password);
                } catch (\Exception $e) {
                    $components = false;
                }
                if ($components !== false) {
                    break;
                }
            }
        } else {
            $format = strtolower($type);
            if (isset(self::$fileFormats[$format])) {
                $format = self::$fileFormats[$format];
                try {
                    $components = $format::load($key, $this->password);
                } catch (\Exception $e) {
                    $components = false;
                }
            }
        }

        if ($components === false) {
            $this->format = false;
            return false;
        }

        $this->format = $format;

        if (empty($this->modulus) || !$this->modulus->equals($components['modulus'])) {
            $this->modulus = $components['modulus'];
            $this->exponent = $this->publicExponent = $components['publicExponent'];
            return true;
        }

        $this->publicExponent = $components['publicExponent'];

        return true;
    }

    /**
     * Defines the private key
     *
     * If phpseclib guessed a private key was a public key and loaded it as such it might be desirable to force
     * phpseclib to treat the key as a private key. This function will do that.
     *
     * Do note that when a new key is loaded the index will be cleared.
     *
     * Returns true on success, false on failure
     *
     * @see self::getPublicKey()
     * @access public
     * @param string $key optional
     * @param int $type optional
     * @return bool
     */
    public function setPrivateKey($key = false, $type = false)
    {
        if ($key === false && !empty($this->publicExponent)) {
            $this->publicExponent = false;
            return true;
        }

        $rsa = new RSA();
        if (!$rsa->load($key, $type)) {
            return false;
        }
        $rsa->publicExponent = false;

        // don't overwrite the old key if the new key is invalid
        $this->load($rsa);
        return true;
    }

    /**
     * Returns the public key
     *
     * The public key is only returned under two circumstances - if the private key had the public key embedded within it
     * or if the public key was set via setPublicKey().  If the currently loaded key is supposed to be the public key this
     * function won't return it since this library, for the most part, doesn't distinguish between public and private keys.
     *
     * @see self::getPrivateKey()
     * @access public
     * @param string $type optional
     * @return mixed
     */
    public function getPublicKey($type = 'PKCS8')
    {
        $type = strtolower($type);
        if (!isset(self::$fileFormats[$type])) {
            return false;
        }
        $type = self::$fileFormats[$type];
        if (!method_exists($type, 'savePublicKey')) {
            return false;
        }

        if (empty($this->modulus) || empty($this->publicExponent)) {
            return false;
        }

        return $type::savePublicKey($this->modulus, $this->publicExponent);
    }

    /**
     * Returns the public key's fingerprint
     *
     * The public key's fingerprint is returned, which is equivalent to running `ssh-keygen -lf rsa.pub`. If there is
     * no public key currently loaded, false is returned.
     * Example output (md5): "c1:b1:30:29:d7:b8:de:6c:97:77:10:d7:46:41:63:87" (as specified by RFC 4716)
     *
     * @access public
     * @param string $algorithm The hashing algorithm to be used. Valid options are 'md5' and 'sha256'. False is returned
     * for invalid values.
     * @return mixed
     */
    public function getPublicKeyFingerprint($algorithm = 'md5')
    {
        if (empty($this->modulus) || empty($this->publicExponent)) {
            return false;
        }

        $modulus = $this->modulus->toBytes(true);
        $publicExponent = $this->publicExponent->toBytes(true);

        $RSAPublicKey = pack('Na*Na*Na*', strlen('ssh-rsa'), 'ssh-rsa', strlen($publicExponent), $publicExponent, strlen($modulus), $modulus);

        switch ($algorithm) {
            case 'sha256':
                $hash = new Hash('sha256');
                $base = Base64::encode($hash->hash($RSAPublicKey));
                return substr($base, 0, strlen($base) - 1);
            case 'md5':
                return substr(chunk_split(md5($RSAPublicKey), 2, ':'), 0, -1);
            default:
                return false;
        }
    }

    /**
     * Returns a minimalistic private key
     *
     * Returns the private key without the prime number constituants.  Structurally identical to a public key that
     * hasn't been set as the public key
     *
     * @see self::getPrivateKey()
     * @access private
     * @param string $type optional
     * @return mixed
     */
    private function getPrivatePublicKey($type = 'PKCS8')
    {
        $type = strtolower($type);
        if (!isset(self::$fileFormats[$type])) {
            return false;
        }
        $type = self::$fileFormats[$type];
        if (!method_exists($type, 'savePublicKey')) {
            return false;
        }

        if (empty($this->modulus) || empty($this->exponent)) {
            return false;
        }

        $oldFormat = $this->publicKeyFormat;
        $this->publicKeyFormat = $type;
        $temp = $type::savePublicKey($this->modulus, $this->exponent);
        $this->publicKeyFormat = $oldFormat;
        return $temp;
    }


    /**
     * __toString() magic method
     *
     * @access public
     * @return string
     */
    public function __toString()
    {
        try {
            $key = $this->getPrivateKey($this->privateKeyFormat);
            if (is_string($key)) {
                return $key;
            }
            $key = $this->getPrivatePublicKey($this->publicKeyFormat);
            return is_string($key) ? $key : '';
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * __clone() magic method
     *
     * @access public
     * @return \phpseclib\Crypt\RSA
     */
    public function __clone()
    {
        $key = new RSA();
        $key->load($this);
        return $key;
    }

    /**
     * Determines the private key format
     *
     * @see self::__toString()
     * @access public
     * @param string $format
     */
    public function setPrivateKeyFormat($format)
    {
        $this->privateKeyFormat = $format;
    }

    /**
     * Determines the public key format
     *
     * @see self::__toString()
     * @access public
     * @param string $format
     */
    public function setPublicKeyFormat($format)
    {
        $this->publicKeyFormat = $format;
    }

    /**
     * Determines which hashing function should be used
     *
     * Used with signature production / verification and (if the encryption mode is self::PADDING_OAEP) encryption and
     * decryption.  If $hash isn't supported, sha256 is used.
     *
     * @access public
     * @param string $hash
     */
    public function setHash($hash)
    {
        // \phpseclib\Crypt\Hash supports algorithms that PKCS#1 doesn't support.  md5-96 and sha1-96, for example.
        switch ($hash) {
            case 'md2':
            case 'md5':
            case 'sha1':
            case 'sha256':
            case 'sha384':
            case 'sha512':
            case 'sha224':
            case 'sha512/224':
            case 'sha512/256':
                $this->hash = new Hash($hash);
                $this->hashName = $hash;
                break;
            default:
                $this->hash = new Hash('sha256');
                $this->hashName = 'sha256';
        }
        $this->hLen = $this->hash->getLengthInBytes();
    }

    /**
     * Determines which hashing function should be used for the mask generation function
     *
     * The mask generation function is used by self::PADDING_OAEP and self::PADDING_PSS and although it's
     * best if Hash and MGFHash are set to the same thing this is not a requirement.
     *
     * @access public
     * @param string $hash
     */
    public function setMGFHash($hash)
    {
        // \phpseclib\Crypt\Hash supports algorithms that PKCS#1 doesn't support.  md5-96 and sha1-96, for example.
        switch ($hash) {
            case 'md2':
            case 'md5':
            case 'sha1':
            case 'sha256':
            case 'sha384':
            case 'sha512':
            case 'sha224':
            case 'sha512/224':
            case 'sha512/256':
                $this->mgfHash = new Hash($hash);
                break;
            default:
                $this->mgfHash = new Hash('sha256');
        }
        $this->mgfHLen = $this->mgfHash->getLengthInBytes();
    }

    /**
     * Determines the salt length
     *
     * To quote from {@link http://tools.ietf.org/html/rfc3447#page-38 RFC3447#page-38}:
     *
     *    Typical salt lengths in octets are hLen (the length of the output
     *    of the hash function Hash) and 0.
     *
     * @access public
     * @param int $format
     */
    public function setSaltLength($sLen)
    {
        $this->sLen = $sLen;
    }

    /**
     * Integer-to-Octet-String primitive
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-4.1 RFC3447#section-4.1}.
     *
     * @access private
     * @param bool|\phpseclib\Math\BigInteger $x
     * @param int $xLen
     * @return bool|string
     */
    private function i2osp($x, $xLen)
    {
        if ($x === false) {
            return false;
        }
        $x = $x->toBytes();
        if (strlen($x) > $xLen) {
            return false;
        }
        return str_pad($x, $xLen, chr(0), STR_PAD_LEFT);
    }

    /**
     * Octet-String-to-Integer primitive
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-4.2 RFC3447#section-4.2}.
     *
     * @access private
     * @param string $x
     * @return \phpseclib\Math\BigInteger
     */
    private function os2ip($x)
    {
        return new BigInteger($x, 256);
    }

    /**
     * Exponentiate with or without Chinese Remainder Theorem
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.1 RFC3447#section-5.1.2}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $x
     * @return \phpseclib\Math\BigInteger
     */
    private function exponentiate($x)
    {
        switch (true) {
            case empty($this->primes):
            case $this->primes[1]->equals(self::$zero):
            case empty($this->coefficients):
            case $this->coefficients[2]->equals(self::$zero):
            case empty($this->exponents):
            case $this->exponents[1]->equals(self::$zero):
                return $x->modPow($this->exponent, $this->modulus);
        }

        $num_primes = count($this->primes);

        if (defined('CRYPT_RSA_DISABLE_BLINDING')) {
            $m_i = [
                1 => $x->modPow($this->exponents[1], $this->primes[1]),
                2 => $x->modPow($this->exponents[2], $this->primes[2])
            ];
            $h = $m_i[1]->subtract($m_i[2]);
            $h = $h->multiply($this->coefficients[2]);
            list(, $h) = $h->divide($this->primes[1]);
            $m = $m_i[2]->add($h->multiply($this->primes[2]));

            $r = $this->primes[1];
            for ($i = 3; $i <= $num_primes; $i++) {
                $m_i = $x->modPow($this->exponents[$i], $this->primes[$i]);

                $r = $r->multiply($this->primes[$i - 1]);

                $h = $m_i->subtract($m);
                $h = $h->multiply($this->coefficients[$i]);
                list(, $h) = $h->divide($this->primes[$i]);

                $m = $m->add($r->multiply($h));
            }
        } else {
            $smallest = $this->primes[1];
            for ($i = 2; $i <= $num_primes; $i++) {
                if ($smallest->compare($this->primes[$i]) > 0) {
                    $smallest = $this->primes[$i];
                }
            }

            $r = BigInteger::randomRange(self::$one, $smallest->subtract(self::$one));

            $m_i = [
                1 => $this->blind($x, $r, 1),
                2 => $this->blind($x, $r, 2)
            ];
            $h = $m_i[1]->subtract($m_i[2]);
            $h = $h->multiply($this->coefficients[2]);
            list(, $h) = $h->divide($this->primes[1]);
            $m = $m_i[2]->add($h->multiply($this->primes[2]));

            $r = $this->primes[1];
            for ($i = 3; $i <= $num_primes; $i++) {
                $m_i = $this->blind($x, $r, $i);

                $r = $r->multiply($this->primes[$i - 1]);

                $h = $m_i->subtract($m);
                $h = $h->multiply($this->coefficients[$i]);
                list(, $h) = $h->divide($this->primes[$i]);

                $m = $m->add($r->multiply($h));
            }
        }

        return $m;
    }

    /**
     * Performs RSA Blinding
     *
     * Protects against timing attacks by employing RSA Blinding.
     * Returns $x->modPow($this->exponents[$i], $this->primes[$i])
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $x
     * @param \phpseclib\Math\BigInteger $r
     * @param int $i
     * @return \phpseclib\Math\BigInteger
     */
    private function blind($x, $r, $i)
    {
        $x = $x->multiply($r->modPow($this->publicExponent, $this->primes[$i]));
        $x = $x->modPow($this->exponents[$i], $this->primes[$i]);

        $r = $r->modInverse($this->primes[$i]);
        $x = $x->multiply($r);
        list(, $x) = $x->divide($this->primes[$i]);

        return $x;
    }

    /**
     * Performs blinded RSA equality testing
     *
     * Protects against a particular type of timing attack described.
     *
     * See {@link http://codahale.com/a-lesson-in-timing-attacks/ A Lesson In Timing Attacks (or, Don't use MessageDigest.isEquals)}
     *
     * Thanks for the heads up singpolyma!
     *
     * @access private
     * @param string $x
     * @param string $y
     * @return bool
     */
    private static function equals($x, $y)
    {
        if (strlen($x) != strlen($y)) {
            return false;
        }

        $result = 0;
        for ($i = 0; $i < strlen($x); $i++) {
            $result |= ord($x[$i]) ^ ord($y[$i]);
        }

        return $result == 0;
    }

    /**
     * RSAEP
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.1 RFC3447#section-5.1.1}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $m
     * @return bool|\phpseclib\Math\BigInteger
     */
    private function rsaep($m)
    {
        if ($m->compare(self::$zero) < 0 || $m->compare($this->modulus) > 0) {
            return false;
        }
        return $this->exponentiate($m);
    }

    /**
     * RSADP
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.2 RFC3447#section-5.1.2}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $c
     * @return bool|\phpseclib\Math\BigInteger
     */
    private function rsadp($c)
    {
        if ($c->compare(self::$zero) < 0 || $c->compare($this->modulus) > 0) {
            return false;
        }
        return $this->exponentiate($c);
    }

    /**
     * RSASP1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.2.1 RFC3447#section-5.2.1}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $m
     * @return bool|\phpseclib\Math\BigInteger
     */
    private function rsasp1($m)
    {
        if ($m->compare(self::$zero) < 0 || $m->compare($this->modulus) > 0) {
            return false;
        }
        return $this->exponentiate($m);
    }

    /**
     * RSAVP1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.2.2 RFC3447#section-5.2.2}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $s
     * @return bool|\phpseclib\Math\BigInteger
     */
    private function rsavp1($s)
    {
        if ($s->compare(self::$zero) < 0 || $s->compare($this->modulus) > 0) {
            return false;
        }
        return $this->exponentiate($s);
    }

    /**
     * MGF1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#appendix-B.2.1 RFC3447#appendix-B.2.1}.
     *
     * @access private
     * @param string $mgfSeed
     * @param int $mgfLen
     * @return string
     */
    private function mgf1($mgfSeed, $maskLen)
    {
        // if $maskLen would yield strings larger than 4GB, PKCS#1 suggests a "Mask too long" error be output.

        $t = '';
        $count = ceil($maskLen / $this->mgfHLen);
        for ($i = 0; $i < $count; $i++) {
            $c = pack('N', $i);
            $t.= $this->mgfHash->hash($mgfSeed . $c);
        }

        return substr($t, 0, $maskLen);
    }

    /**
     * RSAES-OAEP-ENCRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.1.1 RFC3447#section-7.1.1} and
     * {http://en.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding OAES}.
     *
     * @access private
     * @param string $m
     * @param string $l
     * @throws \OutOfBoundsException if strlen($m) > $this->k - 2 * $this->hLen - 2
     * @return string
     */
    private function rsaes_oaep_encrypt($m, $l = '')
    {
        $mLen = strlen($m);

        // Length checking

        // if $l is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        if ($mLen > $this->k - 2 * $this->hLen - 2) {
            throw new \OutOfBoundsException('Message too long');
        }

        // EME-OAEP encoding

        $lHash = $this->hash->hash($l);
        $ps = str_repeat(chr(0), $this->k - $mLen - 2 * $this->hLen - 2);
        $db = $lHash . $ps . chr(1) . $m;
        $seed = Random::string($this->hLen);
        $dbMask = $this->mgf1($seed, $this->k - $this->hLen - 1);
        $maskedDB = $db ^ $dbMask;
        $seedMask = $this->mgf1($maskedDB, $this->hLen);
        $maskedSeed = $seed ^ $seedMask;
        $em = chr(0) . $maskedSeed . $maskedDB;

        // RSA encryption

        $m = $this->os2ip($em);
        $c = $this->rsaep($m);
        $c = $this->i2osp($c, $this->k);

        // Output the ciphertext C

        return $c;
    }

    /**
     * RSAES-OAEP-DECRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.1.2 RFC3447#section-7.1.2}.  The fact that the error
     * messages aren't distinguishable from one another hinders debugging, but, to quote from RFC3447#section-7.1.2:
     *
     *    Note.  Care must be taken to ensure that an opponent cannot
     *    distinguish the different error conditions in Step 3.g, whether by
     *    error message or timing, or, more generally, learn partial
     *    information about the encoded message EM.  Otherwise an opponent may
     *    be able to obtain useful information about the decryption of the
     *    ciphertext C, leading to a chosen-ciphertext attack such as the one
     *    observed by Manger [36].
     *
     * As for $l...  to quote from {@link http://tools.ietf.org/html/rfc3447#page-17 RFC3447#page-17}:
     *
     *    Both the encryption and the decryption operations of RSAES-OAEP take
     *    the value of a label L as input.  In this version of PKCS #1, L is
     *    the empty string; other uses of the label are outside the scope of
     *    this document.
     *
     * @access private
     * @param string $c
     * @param string $l
     * @return bool|string
     */
    private function rsaes_oaep_decrypt($c, $l = '')
    {
        // Length checking

        // if $l is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        if (strlen($c) != $this->k || $this->k < 2 * $this->hLen + 2) {
            return false;
        }

        // RSA decryption

        $c = $this->os2ip($c);
        $m = $this->rsadp($c);
        $em = $this->i2osp($m, $this->k);
        if ($em === false) {
            return false;
        }

        // EME-OAEP decoding

        $lHash = $this->hash->hash($l);
        $y = ord($em[0]);
        $maskedSeed = substr($em, 1, $this->hLen);
        $maskedDB = substr($em, $this->hLen + 1);
        $seedMask = $this->mgf1($maskedDB, $this->hLen);
        $seed = $maskedSeed ^ $seedMask;
        $dbMask = $this->mgf1($seed, $this->k - $this->hLen - 1);
        $db = $maskedDB ^ $dbMask;
        $lHash2 = substr($db, 0, $this->hLen);
        $m = substr($db, $this->hLen);
        if (!self::equals($lHash, $lHash2)) {
            return false;
        }
        $m = ltrim($m, chr(0));
        if (ord($m[0]) != 1) {
            return false;
        }

        // Output the message M

        return substr($m, 1);
    }

    /**
     * Raw Encryption / Decryption
     *
     * Doesn't use padding and is not recommended.
     *
     * @access private
     * @param string $m
     * @return bool|string
     * @throws \OutOfBoundsException if strlen($m) > $this->k
     */
    private function raw_encrypt($m)
    {
        if (strlen($m) > $this->k) {
            throw new \OutOfBoundsException('Message too long');
        }

        $temp = $this->os2ip($m);
        $temp = $this->rsaep($temp);
        return  $this->i2osp($temp, $this->k);
    }

    /**
     * RSAES-PKCS1-V1_5-ENCRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.2.1 RFC3447#section-7.2.1}.
     *
     * @access private
     * @param string $m
     * @param bool $pkcs15_compat optional
     * @throws \OutOfBoundsException if strlen($m) > $this->k - 11
     * @return bool|string
     */
    private function rsaes_pkcs1_v1_5_encrypt($m, $pkcs15_compat = false)
    {
        $mLen = strlen($m);

        // Length checking

        if ($mLen > $this->k - 11) {
            throw new \OutOfBoundsException('Message too long');
        }

        // EME-PKCS1-v1_5 encoding

        $psLen = $this->k - $mLen - 3;
        $ps = '';
        while (strlen($ps) != $psLen) {
            $temp = Random::string($psLen - strlen($ps));
            $temp = str_replace("\x00", '', $temp);
            $ps.= $temp;
        }
        $type = 2;
        // see the comments of _rsaes_pkcs1_v1_5_decrypt() to understand why this is being done
        if ($pkcs15_compat && (!isset($this->publicExponent) || $this->exponent !== $this->publicExponent)) {
            $type = 1;
            // "The padding string PS shall consist of k-3-||D|| octets. ... for block type 01, they shall have value FF"
            $ps = str_repeat("\xFF", $psLen);
        }
        $em = chr(0) . chr($type) . $ps . chr(0) . $m;

        // RSA encryption
        $m = $this->os2ip($em);
        $c = $this->rsaep($m);
        $c = $this->i2osp($c, $this->k);

        // Output the ciphertext C

        return $c;
    }

    /**
     * RSAES-PKCS1-V1_5-DECRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.2.2 RFC3447#section-7.2.2}.
     *
     * For compatibility purposes, this function departs slightly from the description given in RFC3447.
     * The reason being that RFC2313#section-8.1 (PKCS#1 v1.5) states that ciphertext's encrypted by the
     * private key should have the second byte set to either 0 or 1 and that ciphertext's encrypted by the
     * public key should have the second byte set to 2.  In RFC3447 (PKCS#1 v2.1), the second byte is supposed
     * to be 2 regardless of which key is used.  For compatibility purposes, we'll just check to make sure the
     * second byte is 2 or less.  If it is, we'll accept the decrypted string as valid.
     *
     * As a consequence of this, a private key encrypted ciphertext produced with \phpseclib\Crypt\RSA may not decrypt
     * with a strictly PKCS#1 v1.5 compliant RSA implementation.  Public key encrypted ciphertext's should but
     * not private key encrypted ciphertext's.
     *
     * @access private
     * @param string $c
     * @return bool|string
     */
    private function rsaes_pkcs1_v1_5_decrypt($c)
    {
        // Length checking

        if (strlen($c) != $this->k) { // or if k < 11
            return false;
        }

        // RSA decryption

        $c = $this->os2ip($c);
        $m = $this->rsadp($c);
        $em = $this->i2osp($m, $this->k);
        if ($em === false) {
            return false;
        }

        // EME-PKCS1-v1_5 decoding

        if (ord($em[0]) != 0 || ord($em[1]) > 2) {
            return false;
        }

        $ps = substr($em, 2, strpos($em, chr(0), 2) - 2);
        $m = substr($em, strlen($ps) + 3);

        if (strlen($ps) < 8) {
            return false;
        }

        // Output M

        return $m;
    }

    /**
     * EMSA-PSS-ENCODE
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.1.1 RFC3447#section-9.1.1}.
     *
     * @access private
     * @param string $m
     * @throws \RuntimeException on encoding error
     * @param int $emBits
     */
    private function emsa_pss_encode($m, $emBits)
    {
        // if $m is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        $emLen = ($emBits + 1) >> 3; // ie. ceil($emBits / 8)
        $sLen = $this->sLen !== null ? $this->sLen : $this->hLen;

        $mHash = $this->hash->hash($m);
        if ($emLen < $this->hLen + $sLen + 2) {
            return false;
        }

        $salt = Random::string($sLen);
        $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
        $h = $this->hash->hash($m2);
        $ps = str_repeat(chr(0), $emLen - $sLen - $this->hLen - 2);
        $db = $ps . chr(1) . $salt;
        $dbMask = $this->mgf1($h, $emLen - $this->hLen - 1);
        $maskedDB = $db ^ $dbMask;
        $maskedDB[0] = ~chr(0xFF << ($emBits & 7)) & $maskedDB[0];
        $em = $maskedDB . $h . chr(0xBC);

        return $em;
    }

    /**
     * EMSA-PSS-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.1.2 RFC3447#section-9.1.2}.
     *
     * @access private
     * @param string $m
     * @param string $em
     * @param int $emBits
     * @return string
     */
    private function emsa_pss_verify($m, $em, $emBits)
    {
        // if $m is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        $emLen = ($emBits + 1) >> 3; // ie. ceil($emBits / 8);
        $sLen = $this->sLen !== null ? $this->sLen : $this->hLen;

        $mHash = $this->hash->hash($m);
        if ($emLen < $this->hLen + $sLen + 2) {
            return false;
        }

        if ($em[strlen($em) - 1] != chr(0xBC)) {
            return false;
        }

        $maskedDB = substr($em, 0, -$this->hLen - 1);
        $h = substr($em, -$this->hLen - 1, $this->hLen);
        $temp = chr(0xFF << ($emBits & 7));
        if ((~$maskedDB[0] & $temp) != $temp) {
            return false;
        }
        $dbMask = $this->mgf1($h, $emLen - $this->hLen - 1);
        $db = $maskedDB ^ $dbMask;
        $db[0] = ~chr(0xFF << ($emBits & 7)) & $db[0];
        $temp = $emLen - $this->hLen - $sLen - 2;
        if (substr($db, 0, $temp) != str_repeat(chr(0), $temp) || ord($db[$temp]) != 1) {
            return false;
        }
        $salt = substr($db, $temp + 1); // should be $sLen long
        $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
        $h2 = $this->hash->hash($m2);
        return self::equals($h, $h2);
    }

    /**
     * RSASSA-PSS-SIGN
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.1.1 RFC3447#section-8.1.1}.
     *
     * @access private
     * @param string $m
     * @return bool|string
     */
    private function rsassa_pss_sign($m)
    {
        // EMSA-PSS encoding

        $em = $this->emsa_pss_encode($m, 8 * $this->k - 1);

        // RSA signature

        $m = $this->os2ip($em);
        $s = $this->rsasp1($m);
        $s = $this->i2osp($s, $this->k);

        // Output the signature S

        return $s;
    }

    /**
     * RSASSA-PSS-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.1.2 RFC3447#section-8.1.2}.
     *
     * @access private
     * @param string $m
     * @param string $s
     * @return bool|string
     */
    private function rsassa_pss_verify($m, $s)
    {
        // Length checking

        if (strlen($s) != $this->k) {
            return false;
        }

        // RSA verification

        $modBits = 8 * $this->k;

        $s2 = $this->os2ip($s);
        $m2 = $this->rsavp1($s2);
        $em = $this->i2osp($m2, $modBits >> 3);
        if ($em === false) {
            return false;
        }

        // EMSA-PSS verification

        return $this->emsa_pss_verify($m, $em, $modBits - 1);
    }

    /**
     * EMSA-PKCS1-V1_5-ENCODE
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.2 RFC3447#section-9.2}.
     *
     * @access private
     * @param string $m
     * @param int $emLen
     * @throws \LengthException if the intended encoded message length is too short
     * @return string
     */
    private function emsa_pkcs1_v1_5_encode($m, $emLen)
    {
        $h = $this->hash->hash($m);

        // see http://tools.ietf.org/html/rfc3447#page-43
        switch ($this->hashName) {
            case 'md2':
                $t = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10";
                break;
            case 'md5':
                $t = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10";
                break;
            case 'sha1':
                $t = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14";
                break;
            case 'sha256':
                $t = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20";
                break;
            case 'sha384':
                $t = "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30";
                break;
            case 'sha512':
                $t = "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40";
                break;
            // from https://www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf#page=40
            case 'sha224':
                $t = "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c";
                break;
            case 'sha512/224':
                $t = "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05\x05\x00\x04\x1c";
                break;
            case 'sha512/256':
                $t = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06\x05\x00\x04\x20";
        }
        $t.= $h;
        $tLen = strlen($t);

        if ($emLen < $tLen + 11) {
            throw new \LengthException('Intended encoded message length too short');
        }

        $ps = str_repeat(chr(0xFF), $emLen - $tLen - 3);

        $em = "\0\1$ps\0$t";

        return $em;
    }

    /**
     * RSASSA-PKCS1-V1_5-SIGN
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.2.1 RFC3447#section-8.2.1}.
     *
     * @access private
     * @param string $m
     * @throws \LengthException if the RSA modulus is too short
     * @return bool|string
     */
    private function rsassa_pkcs1_v1_5_sign($m)
    {
        // EMSA-PKCS1-v1_5 encoding

        // If the encoding operation outputs "intended encoded message length too short," output "RSA modulus
        // too short" and stop.
        try {
            $em = $this->emsa_pkcs1_v1_5_encode($m, $this->k);
        } catch (\LengthException $e) {
            throw new \LengthException('RSA modulus too short');
        }

        // RSA signature

        $m = $this->os2ip($em);
        $s = $this->rsasp1($m);
        $s = $this->i2osp($s, $this->k);

        // Output the signature S

        return $s;
    }

    /**
     * RSASSA-PKCS1-V1_5-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.2.2 RFC3447#section-8.2.2}.
     *
     * @access private
     * @param string $m
     * @param string $s
     * @throws \LengthException if the RSA modulus is too short
     * @return bool
     */
    private function rsassa_pkcs1_v1_5_verify($m, $s)
    {
        // Length checking

        if (strlen($s) != $this->k) {
            return false;
        }

        // RSA verification

        $s = $this->os2ip($s);
        $m2 = $this->rsavp1($s);
        $em = $this->i2osp($m2, $this->k);
        if ($em === false) {
            return false;
        }

        // EMSA-PKCS1-v1_5 encoding

        // If the encoding operation outputs "intended encoded message length too short," output "RSA modulus
        // too short" and stop.
        try {
            $em2 = $this->emsa_pkcs1_v1_5_encode($m, $this->k);
        } catch (\LengthException $e) {
            throw new \LengthException('RSA modulus too short');
        }

        // Compare
        return self::equals($em, $em2);
    }

    /**
     * RSASSA-PKCS1-V1_5-VERIFY (relaxed matching)
     *
     * Per {@link http://tools.ietf.org/html/rfc3447#page-43 RFC3447#page-43} PKCS1 v1.5
     * specified the use BER encoding rather than DER encoding that PKCS1 v2.0 specified.
     * This means that under rare conditions you can have a perfectly valid v1.5 signature
     * that fails to validate with _rsassa_pkcs1_v1_5_verify(). PKCS1 v2.1 also recommends
     * that if you're going to validate these types of signatures you "should indicate
     * whether the underlying BER encoding is a DER encoding and hence whether the signature
     * is valid with respect to the specification given in [PKCS1 v2.0+]". so if you do
     * $rsa->getLastPadding() and get RSA::PADDING_RELAXED_PKCS1 back instead of
     * RSA::PADDING_PKCS1... that means BER encoding was used.
     *
     * @access private
     * @param string $m
     * @param string $s
     * @return bool
     */
    private function rsassa_pkcs1_v1_5_relaxed_verify($m, $s)
    {
        // Length checking

        if (strlen($s) != $this->k) {
            return false;
        }

        // RSA verification

        $s = $this->os2ip($s);
        $m2 = $this->rsavp1($s);
        if ($m2 === false) {
            return false;
        }
        $em = $this->i2osp($m2, $this->k);
        if ($em === false) {
            return false;
        }

        if (Strings::shift($em, 2) != "\0\1") {
            return false;
        }

        $em = ltrim($em, "\xFF");
        if (Strings::shift($em) != "\0") {
            return false;
        }

        $decoded = ASN1::decodeBER($em);
        if (!is_array($decoded) || empty($decoded[0]) || strlen($em) > $decoded[0]['length']) {
            return false;
        }

        static $oids;
        if (!isset($oids)) {
            $oids = [
                '1.2.840.113549.2.2' => 'md2',
                '1.2.840.113549.2.4' => 'md4', // from PKCS1 v1.5
                '1.2.840.113549.2.5' => 'md5',
                '1.3.14.3.2.26' => 'id-sha1',
                '2.16.840.1.101.3.4.2.1' => 'id-sha256',
                '2.16.840.1.101.3.4.2.2' => 'id-sha384',
                '2.16.840.1.101.3.4.2.3' => 'id-sha512',
                // from PKCS1 v2.2
                '2.16.840.1.101.3.4.2.4' => 'id-sha224',
                '2.16.840.1.101.3.4.2.5' => 'id-sha512/224',
                '2.16.840.1.101.3.4.2.6' => 'id-sha512/256',
            ];
            ASN1::loadOIDs($oids);
        }

        $decoded = ASN1::asn1map($decoded[0], DigestInfo::MAP);
        if (!isset($decoded) || $decoded === false) {
            return false;
        }

        if (!in_array($decoded['digestAlgorithm']['algorithm'], $oids)) {
            return false;
        }

        $hash = $decoded['digestAlgorithm']['algorithm'];
        $hash = substr($hash, 0, 3) == 'id-' ?
            substr($hash, 3) :
            $hash;
        $hash = new Hash($hash);
        $em = $hash->hash($m);
        $em2 = $decoded['digest'];

        return self::equals($em, $em2);
    }

    /**
     * Encryption
     *
     * Both self::PADDING_OAEP and self::PADDING_PKCS1 both place limits on how long $plaintext can be.
     * If $plaintext exceeds those limits it will be broken up so that it does and the resultant ciphertext's will
     * be concatenated together.
     *
     * @see self::decrypt()
     * @access public
     * @param string $plaintext
     * @param int $padding optional
     * @return bool|string
     * @throws \LengthException if the RSA modulus is too short
     */
    public function encrypt($plaintext, $padding = self::PADDING_OAEP)
    {
        switch ($padding) {
            case self::PADDING_NONE:
                return $this->raw_encrypt($plaintext);
            case self::PADDING_PKCS15_COMPAT:
            case self::PADDING_PKCS1:
                return $this->rsaes_pkcs1_v1_5_encrypt($plaintext, $padding == self::PADDING_PKCS15_COMPAT);
            //case self::PADDING_OAEP:
            default:
                return $this->rsaes_oaep_encrypt($plaintext);
        }
    }

    /**
     * Decryption
     *
     * @see self::encrypt()
     * @access public
     * @param string $plaintext
     * @param int $padding optional
     * @return bool|string
     */
    public function decrypt($ciphertext, $padding = self::PADDING_OAEP)
    {
        switch ($padding) {
            case self::PADDING_NONE:
                return $this->raw_encrypt($ciphertext);
            case self::PADDING_PKCS1:
                return $this->rsaes_pkcs1_v1_5_decrypt($ciphertext);
            //case self::PADDING_OAEP:
            default:
                return $this->rsaes_oaep_decrypt($ciphertext);
        }
    }

    /**
     * Create a signature
     *
     * @see self::verify()
     * @access public
     * @param string $message
     * @param int $padding optional
     * @return string
     */
    public function sign($message, $padding = self::PADDING_PSS)
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            return false;
        }

        switch ($padding) {
            case self::PADDING_PKCS1:
            case self::PADDING_RELAXED_PKCS1:
                return $this->rsassa_pkcs1_v1_5_sign($message);
            //case self::PADDING_PSS:
            default:
                return $this->rsassa_pss_sign($message);
        }
    }

    /**
     * Verifies a signature
     *
     * @see self::sign()
     * @access public
     * @param string $message
     * @param string $signature
     * @param int $padding optional
     * @return bool
     */
    public function verify($message, $signature, $padding = self::PADDING_PSS)
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            return false;
        }

        switch ($padding) {
            case self::PADDING_RELAXED_PKCS1:
                return $this->rsassa_pkcs1_v1_5_relaxed_verify($message, $signature);
            case self::PADDING_PKCS1:
                return $this->rsassa_pkcs1_v1_5_verify($message, $signature);
            //case self::PADDING_PSS:
            default:
                return $this->rsassa_pss_verify($message, $signature);
        }
    }
}
