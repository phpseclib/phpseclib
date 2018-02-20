<?php

/**
 * Base Class for all asymmetric key ciphers
 *
 * PHP version 5
 *
 * @category  Crypt
 * @package   AsymmetricKey
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\Common;

use phpseclib\Math\BigInteger;
use phpseclib\Crypt\Hash;
use ParagonIE\ConstantTime\Base64;

/**
 * Base Class for all stream cipher classes
 *
 * @package AsymmetricKey
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class AsymmetricKey
{
    /**
     * Precomputed Zero
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    protected static $zero;

    /**
     * Precomputed One
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    protected static $one;

    /**
     * Engine
     *
     * This is only used for key generation. Valid values are RSA::ENGINE_INTERNAL and RSA::ENGINE_OPENSSL
     *
     * @var int
     * @access private
     */
    protected static $engine = NULL;

    /**
     * OpenSSL configuration file name.
     *
     * Set to null to use system configuration file.
     *
     * @see self::createKey()
     * @var mixed
     * @access public
     */
    protected static $configFile;

    /**
     * Supported plugins (lower case)
     *
     * @see self::initialize_static_variables()
     * @var array
     * @access private
     */
    private static $plugins = [];

    /**
     * Supported plugins (original case)
     *
     * @see self::initialize_static_variables()
     * @var array
     * @access private
     */
    private static $origPlugins = [];

    /**
     * Supported signature formats (lower case)
     *
     * @see self::initialize_static_variables()
     * @var array
     * @access private
     */
    private static $signatureFormats = [];

    /**
     * Supported signature formats (original case)
     *
     * @see self::initialize_static_variables()
     * @var array
     * @access private
     */
    private static $signatureFileFormats = [];

    /**
     * Password
     *
     * @var string
     * @access private
     */
    protected $password = false;

    /**
     * Loaded File Format
     *
     * @var string
     * @access private
     */
    protected $format = false;

    /**
     * Private Key Format
     *
     * @var string
     * @access private
     */
    protected $privateKeyFormat = 'PKCS8';

    /**
     * Public Key Format
     *
     * @var string
     * @access private
     */
    protected $publicKeyFormat = 'PKCS8';

    /**
     * Hash function
     *
     * @var \phpseclib\Crypt\Hash
     * @access private
     */
    protected $hash;

    /**
     * HMAC function
     *
     * @var \phpseclib\Crypt\Hash
     * @access private
     */
    private $hmac;

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
     * The constructor
     *
     * @access public
     */
    public function __construct()
    {
        self::initialize_static_variables();

        $this->hash = new Hash('sha256');
        $this->hmac = new Hash('sha256');
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
        static::$engine = null;
        $candidateEngines = [
            $val,
            self::ENGINE_OPENSSL
        ];
        foreach ($candidateEngines as $engine) {
            if (static::isValidEngine($engine)) {
                static::$engine = $engine;
                break;
            }
        }
        if (!isset(static::$engine)) {
            static::$engine = self::ENGINE_INTERNAL;
        }
    }

    /**
     * Returns the engine
     *
     * @access public
     * @return int
     */
    public static function getEngine()
    {
        return self::$engine;
    }

    /**
     * Initialize static variables
     *
     * @access private
     */
    protected static function initialize_static_variables()
    {
        if (!isset(self::$zero)) {
            self::$zero= new BigInteger(0);
            self::$one = new BigInteger(1);
            self::$configFile = __DIR__ . '/../openssl.cnf';
        }

        self::loadPlugins('Keys');
        if (static::ALGORITHM != 'RSA') {
            self::loadPlugins('Signature');
        }
    }

    /**
     * Load Plugins
     *
     * @params $format
     * @access private
     */
    private static function loadPlugins($format)
    {
        if (!isset(self::$plugins[static::ALGORITHM][$format])) {
            self::$plugins[static::ALGORITHM][$format] = [];
            foreach (new \DirectoryIterator(__DIR__ . '/../' . static::ALGORITHM . '/' . $format . '/') as $file) {
                if ($file->getExtension() !== 'php') continue;
                $name = pathinfo($file, PATHINFO_FILENAME);
                $type = 'phpseclib\Crypt\\' . static::ALGORITHM . '\\' . $format . '\\' . $name;
                self::$plugins[static::ALGORITHM][$format][strtolower($name)] = $type;
                self::$origPlugins[static::ALGORITHM][$format][] = $name;
            }
        }
    }

    /**
     * Validate Plugin
     *
     * @access private
     * @param string $format
     * @param string $type
     * @param string $method optional
     * @return mixed
     */
    protected static function validatePlugin($format, $type, $method = NULL)
    {
        $type = strtolower($type);
        if (!isset(self::$plugins[static::ALGORITHM][$format][$type])) {
            return false;
        }
        $type = self::$plugins[static::ALGORITHM][$format][$type];
        if (isset($method) && !method_exists($type, $method)) {
            return false;
        }

        return $type;
    }

    /**
     * Load the key
     *
     * @access private
     * @param string $key
     * @param string $type
     * @return array|bool
     */
    public function load($key, $type)
    {
        $components = false;
        if ($type === false) {
            foreach (self::$plugins[static::ALGORITHM]['Keys'] as $format) {
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
            if (isset(self::$plugins[static::ALGORITHM]['Keys'][$format])) {
                $format = self::$plugins[static::ALGORITHM]['Keys'][$format];
                $components = $format::load($key, $this->password);
            }
        }

        if ($components === false) {
            $this->format = false;
            return false;
        }

        $this->format = $format;

        return $components;
    }

    /**
     * Load the public key
     *
     * @access private
     * @param string $key
     * @param string $type
     * @return array|bool
     */
    public function setPublicKey($key, $type)
    {
        $components = false;
        if ($type === false) {
            foreach (self::$plugins[static::ALGORITHM]['Keys'] as $format) {
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
            if (isset(self::$plugins[static::ALGORITHM]['Keys'][$format])) {
                $format = self::$plugins[static::ALGORITHM]['Keys'][$format];
                $components = $format::load($key, $this->password);
            }
        }

        if ($components === false) {
            $this->format = false;
            return false;
        }

        $this->format = $format;

        return $components;
    }

    /**
     * Returns a list of supported formats.
     *
     * @access public
     * @return array
     */
    public static function getSupportedKeyFormats()
    {
        self::initialize_static_variables();

        return self::$plugins[static::ALGORITHM]['Keys'];
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
            self::$plugins[static::ALGORITHM]['Keys'][strtolower($shortname)] = $fullname;
            self::$origPlugins[static::ALGORITHM]['Keys'][] = $shortname;
        }
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
        $type = self::validatePlugin('Keys', 'OpenSSH', 'getBinaryOutput');
        if ($type === false) {
            return false;
        }

        $status = $type::getBinaryOutput();
        $type::setBinaryOutput(true);

        $key = $this->getPublicKey('OpenSSH');
        if ($key === false) {
            return false;
        }

        $type::setBinaryOutput($status);

        switch ($algorithm) {
            case 'sha256':
                $hash = new Hash('sha256');
                $base = Base64::encode($hash->hash($key));
                return substr($base, 0, strlen($base) - 1);
            case 'md5':
                return substr(chunk_split(md5($key), 2, ':'), 0, -1);
            default:
                return false;
        }
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
            $key = $this->getPublicKey($this->publicKeyFormat);
            return is_string($key) ? $key : '';
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * __clone() magic method
     *
     * @access public
     * @return static
     */
    public function __clone()
    {
        $key = new static();
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
     * Determines which hashing function should be used
     *
     * @access public
     * @param string $hash
     */
    public function setHash($hash)
    {
        $this->hash = new Hash($hash);
        $this->hmac = new Hash($hash);
    }

    /**
     * Compute the pseudorandom k for signature generation,
     * using the process specified for deterministic DSA.
     *
     * @access public
     * @param string $h1
     * @return string
     */
    protected function computek($h1)
    {
        $v = str_repeat("\1", strlen($h1));

        $k = str_repeat("\0", strlen($h1));

        $x = $this->int2octets($this->x);
        $h1 = $this->bits2octets($h1);

        $this->hmac->setKey($k);
        $k = $this->hmac->hash($v . "\0" . $x . $h1);
        $this->hmac->setKey($k);
        $v = $this->hmac->hash($v);
        $k = $this->hmac->hash($v . "\1" . $x . $h1);
        $this->hmac->setKey($k);
        $v = $this->hmac->hash($v);

        $qlen = $this->q->getLengthInBytes();

        while (true) {
            $t = '';
            while (strlen($t) < $qlen) {
                $v = $this->hmac->hash($v);
                $t = $t . $v;
            }
            $k = $this->bits2int($t);

            if (!$k->equals(self::$zero) && $k->compare($this->q) < 0) {
                break;
            }
            $k = $this->hmac->hash($v . "\0");
            $this->hmac->setKey($k);
            $v = $this->hmac->hash($v);
        }

        return $k;
    }

    /**
     * Integer to Octet String
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $v
     * @return string
     */
    private function int2octets($v)
    {
        $out = $v->toBytes();
        $rolen = $this->q->getLengthInBytes();
        if (strlen($out) < $rolen) {
            return str_pad($out, $rolen, "\0", STR_PAD_LEFT);
        } else if (strlen($out) > $rolen) {
            return substr($out, -$rolen);
        } else {
            return $out;
        }
    }

    /**
     * Bit String to Integer
     *
     * @access private
     * @param string $in
     * @return \phpseclib\Math\BigInteger
     */
    protected function bits2int($in)
    {
        $v = new BigInteger($in, 256);
        $vlen = strlen($in) << 3;
        $qlen = $this->q->getLength();
        if ($vlen > $qlen) {
            return $v->bitwise_rightShift($vlen - $qlen);
        }
        return $v;
    }

    /**
     * Bit String to Octet String
     *
     * @access private
     * @param string $in
     * @return string
     */
    private function bits2octets($in)
    {
        $z1 = $this->bits2int($in);
        $z2 = $z1->subtract($this->q);
        return $z2->compare(self::$zero) < 0 ?
            $this->int2octets($z1) :
            $this->int2octets($z2);
    }
}
