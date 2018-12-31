<?php

/**
 * Pure-PHP FIPS 186-4 compliant implementation of DSA.
 *
 * PHP version 5
 *
 * Here's an example of how to create signatures and verify signatures with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * extract(\phpseclib\Crypt\DSA::createKey());
 *
 * $plaintext = 'terrafrost';
 *
 * $signature = $privatekey->sign($plaintext, 'ASN1');
 *
 * echo $publickey->verify($plaintext, $signature) ? 'verified' : 'unverified';
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   DSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt;

use ParagonIE\ConstantTime\Base64;
use phpseclib\File\ASN1;
use phpseclib\Math\BigInteger;
use phpseclib\Crypt\Common\AsymmetricKey;
use phpseclib\Math\PrimeField;
use phpseclib\Crypt\ECDSA\Signature\ASN1 as ASN1Signature;
use phpseclib\Exception\UnsupportedOperationException;
use phpseclib\Exception\NoKeyLoadedException;
use phpseclib\Exception\InsufficientSetupException;

/**
 * Pure-PHP FIPS 186-4 compliant implementation of DSA.
 *
 * @package DSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class DSA extends AsymmetricKey
{
    /**
     * Algorithm Name
     *
     * @var string
     * @access private
     */
    const ALGORITHM = 'DSA';

    /**
     * DSA Prime P
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    private $p;

    /**
     * DSA Group Order q
     *
     * Prime divisor of p-1
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    protected $q;

    /**
     * DSA Group Generator G
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    private $g;

    /**
     * DSA secret exponent x
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    protected $x;

    /**
     * DSA public key value y
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    private $y;

    /**
     * Create DSA parameters
     *
     * @access public
     * @param int $L
     * @param int $N
     * @return \phpseclib\Crypt\DSA|bool
     */
    public static function createParameters($L = 2048, $N = 224)
    {
        self::initialize_static_variables();

        if (!isset(self::$engines['PHP'])) {
            self::useBestEngine();
        }

        switch (true) {
            case $N == 160:
            /*
              in FIPS 186-1 and 186-2 N was fixed at 160 whereas K had an upper bound of 1024.
              RFC 4253 (SSH Transport Layer Protocol) references FIPS 186-2 and as such most
              SSH DSA implementations only support keys with an N of 160.
              puttygen let's you set the size of L (but not the size of N) and uses 2048 as the
              default L value. that's not really compliant with any of the FIPS standards, however,
              for the purposes of maintaining compatibility with puttygen, we'll support it 
            */
            //case ($L >= 512 || $L <= 1024) && (($L & 0x3F) == 0) && $N == 160:
            // FIPS 186-3 changed this as follows:
            //case $L == 1024 && $N == 160:
            case $L == 2048 && $N == 224:
            case $L == 2048 && $N == 256:
            case $L == 3072 && $N == 256:
                break;
            default:
                return false;
        }

        $two = new BigInteger(2);

        $q = BigInteger::randomPrime($N);
        $divisor = $q->multiply($two);

        do {
            $x = BigInteger::random($L);
            list(, $c) = $x->divide($divisor);
            $p = $x->subtract($c->subtract(self::$one));
        } while ($p->getLength() != $L || !$p->isPrime());

        $p_1 = $p->subtract(self::$one);
        list($e) = $p_1->divide($q);

        // quoting http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf#page=50 ,
        // "h could be obtained from a random number generator or from a counter that
        //  changes after each use". PuTTY (sshdssg.c) starts h off at 1 and increments
        // it on each loop. wikipedia says "commonly h = 2 is used" so we'll just do that
        $h = clone $two;
        while (true) {
            $g = $h->powMod($e, $p);
            if (!$g->equals(self::$one)) {
                break;
            }
            $h = $h->add(self::$one);
        }

        $dsa = new DSA();
        $dsa->p = $p;
        $dsa->q = $q;
        $dsa->g = $g;

        return $dsa;
    }

    /**
     * Create public / private key pair.
     *
     * This method is a bit polymorphic. It can take a DSA object (eg. pre-loaded with parameters),
     * L / N as two distinct parameters or no parameters (at which point L and N will be generated
     * with this method)
     *
     * Returns an array with the following two elements:
     *  - 'privatekey': The private key.
     *  - 'publickey':  The public key.
     *
     * @param $args[]
     * @access public
     * @return array|DSA
     */
    public static function createKey(...$args)
    {
        self::initialize_static_variables();

        if (!isset(self::$engines['PHP'])) {
            self::useBestEngine();
        }

        if (count($args) == 2 && is_int($args[0]) && is_int($args[1])) {
            $private = self::createParameters($args[0], $args[1]);
        } else if (count($args) == 1 && $args[0] instanceof DSA) {
            $private = clone $args[0];
        } else if (!count($args)) {
            $private = self::createParameters();
        } else {
            throw new InsufficientSetupException('Valid parameters are either two integers (L and N), a single DSA object or no parameters at all.');
        }

        $private->x = BigInteger::randomRange(self::$one, $private->q->subtract(self::$one));
        $private->y = $private->g->powMod($private->x, $private->p);

        $public = clone $private;
        unset($public->x);

        return ['privatekey' => $private, 'publickey' => $public];
    }

    /**
     * Loads a public or private key
     *
     * Returns true on success and false on failure (ie. an incorrect password was provided or the key was malformed)
     * @return bool
     * @access public
     * @param string $key
     * @param int|bool $type optional
     */
    public function load($key, $type = false)
    {
        self::initialize_static_variables();

        if (!isset(self::$engines['PHP'])) {
            self::useBestEngine();
        }

        if ($key instanceof DSA) {
            $this->privateKeyFormat = $key->privateKeyFormat;
            $this->publicKeyFormat = $key->publicKeyFormat;
            $this->format = $key->format;
            $this->p = $key->p;
            $this->q = $key->q;
            $this->g = $key->g;
            $this->x = $key->x;
            $this->y = $key->y;
            $this->parametersFormat = $key->parametersFormat;

            return true;
        }

        $components = parent::load($key, $type);
        if ($components === false) {
            $this->format = null;
            $this->p = null;
            $this->q = null;
            $this->g = null;
            $this->x = null;
            $this->y = null;

            return false;
        }

        if (isset($components['p'])) {
            switch (true) {
                case isset($this->p) && !$this->p->equals($components['p']):
                case isset($this->q) && !$this->q->equals($components['q']):
                case isset($this->g) && !$this->g->equals($components['g']):
                    $this->x = $this->y = null;
            }

            $this->p = $components['p'];
            $this->q = $components['q'];
            $this->g = $components['g'];
        }

        $this->x = isset($components['x']) ? $components['x'] : null;

        if (isset($components['y'])) {
            $this->y = $components['y'];
        }
        //} else if (isset($components['x'])) {
        //    $this->y = $this->g->powMod($this->x, $this->p);
        //}

        return true;
    }

    /**
     * Returns the key size
     *
     * More specifically, this L (the length of DSA Prime P) and N (the length of DSA Group Order q)
     *
     * @access public
     * @return array
     */
    public function getLength()
    {
        return isset($this->p) ?
            ['L' => $this->p->getLength(), 'N' => $this->q->getLength()] :
            ['L' => 0, 'N' => 0];
    }

    /**
     * Returns the private key
     *
     * PKCS1 DSA private keys contain x and y. PKCS8 DSA private keys just contain x
     * but y can be derived from x.
     *
     * @see self::getPublicKey()
     * @access public
     * @param string $type optional
     * @return mixed
     */
    public function getPrivateKey($type = 'PKCS8')
    {
        $type = self::validatePlugin('Keys', $type, 'savePrivateKey');
        if ($type === false) {
            return false;
        }

        if (!isset($this->x)) {
            return false;
        }

        if (!isset($this->y)) {
            $this->y = $this->g->powMod($this->x, $this->p);
        }

        return $type::savePrivateKey($this->p, $this->q, $this->g, $this->y, $this->x, $this->password);
    }

    /**
     * Is the key a private key?
     *
     * @access public
     * @return bool
     */
    public function isPrivateKey()
    {
        return isset($this->x);
    }

    /**
     * Is the key a public key?
     *
     * @access public
     * @return bool
     */
    public function isPublicKey()
    {
        return isset($this->p);
    }

    /**
     * Returns the public key
     *
     * If you do "openssl rsa -in private.rsa -pubout -outform PEM" you get a PKCS8 formatted key
     * that contains a publicKeyAlgorithm AlgorithmIdentifier and a publicKey BIT STRING.
     * An AlgorithmIdentifier contains an OID and a parameters field. With RSA public keys this
     * parameters field is NULL. With DSA PKCS8 public keys it is not - it contains the p, q and g
     * variables. The publicKey BIT STRING contains, simply, the y variable. This can be verified
     * by getting a DSA PKCS8 public key:
     *
     * "openssl dsa -in private.dsa -pubout -outform PEM"
     *
     * ie. just swap out rsa with dsa in the rsa command above.
     *
     * A PKCS1 public key corresponds to the publicKey portion of the PKCS8 key. In the case of RSA
     * the publicKey portion /is/ the key. In the case of DSA it is not. You cannot verify a signature
     * without the parameters and the PKCS1 DSA public key format does not include the parameters.
     *
     * @see self::getPrivateKey()
     * @access public
     * @param string $type optional
     * @return mixed
     */
    public function getPublicKey($type = null)
    {
        $returnObj = false;
        if ($type === null) {
            $returnObj = true;
            $type = 'PKCS8';
        }

        $type = self::validatePlugin('Keys', $type, 'savePublicKey');
        if ($type === false) {
            return false;
        }

        if (!isset($this->y)) {
            if (!isset($this->x) || !isset($this->p)) {
                return false;
            }
            $this->y = $this->g->powMod($this->x, $this->p);
        }

        $key = $type::savePublicKey($this->p, $this->q, $this->g, $this->y);
        if (!$returnObj) {
            return $key;
        }

        $public = clone $this;
        $public->load($key, 'PKCS8');

        return $public;
    }

    /**
     * Returns the parameters
     *
     * A public / private key is only returned if the currently loaded "key" contains an x or y
     * value.
     *
     * @see self::getPublicKey()
     * @see self::getPrivateKey()
     * @access public
     * @param string $type optional
     * @return mixed
     */
    public function getParameters($type = 'PKCS1')
    {
        $type = self::validatePlugin('Keys', $type, 'saveParameters');
        if ($type === false) {
            return false;
        }

        if (!isset($this->p) || !isset($this->q) || !isset($this->g)) {
            return false;
        }

        return $type::saveParameters($this->p, $this->q, $this->g);
    }

    /**
     * Returns the current engine being used
     *
     * @see self::useInternalEngine()
     * @see self::useBestEngine()
     * @access public
     * @return string
     */
    public function getEngine()
    {
        return self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods()) ?
            'OpenSSL' : 'PHP';
    }

    /**
     * Create a signature
     *
     * @see self::verify()
     * @access public
     * @param string $message
     * @param string $format optional
     * @return mixed
     */
    public function sign($message, $format = 'ASN1')
    {
        $shortFormat = $format;
        $format = self::validatePlugin('Signature', $format);
        if ($format === false) {
            return false;
        }

        if (empty($this->x)) {
            if (empty($this->y)) {
                throw new NoKeyLoadedException('No key has been loaded');
            }
            throw new UnsupportedOperationException('A public key cannot be used to sign data');
        }

        if (empty($this->p)) {
            throw new InsufficientSetupException('DSA Prime P is not set');
        }

        if (self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods())) {
            $signature = '';
            $result = openssl_sign($message, $signature, $this->getPrivateKey(), $this->hash->getHash());

            if ($result) {
                if ($shortFormat == 'ASN1') {
                    return $signature;
                }

                extract(ASN1Signature::load($signature));

                return $format::save($r, $s);
            }
        }

        $h = $this->hash->hash($message);
        $h = $this->bits2int($h);

        while (true) {
            $k = BigInteger::randomRange(self::$one, $this->q->subtract(self::$one));
            $r = $this->g->powMod($k, $this->p);
            list(, $r) = $r->divide($this->q);
            if ($r->equals(self::$zero)) {
                continue;
            }
            $kinv = $k->modInverse($this->q);
            $temp = $h->add($this->x->multiply($r));
            $temp = $kinv->multiply($temp);
            list(, $s) = $temp->divide($this->q);
            if (!$s->equals(self::$zero)) {
                break;
            }
        }

        // the following is an RFC6979 compliant implementation of deterministic DSA
        // it's unused because it's mainly intended for use when a good CSPRNG isn't
        // available. if phpseclib's CSPRNG isn't good then even key generation is
        // suspect
        /*
        $h1 = $this->hash->hash($message);
        $k = $this->computek($h1);
        $r = $this->g->powMod($k, $this->p);
        list(, $r) = $r->divide($this->q);
        $kinv = $k->modInverse($this->q);
        $h1 = $this->bits2int($h1);
        $temp = $h1->add($this->x->multiply($r));
        $temp = $kinv->multiply($temp);
        list(, $s) = $temp->divide($this->q);
        */

        return $format::save($r, $s);
    }

    /**
     * Verify a signature
     *
     * @see self::verify()
     * @access public
     * @param string $message
     * @param string $signature
     * @param string $format optional
     * @return mixed
     */
    public function verify($message, $signature, $format = 'ASN1')
    {
        $format = self::validatePlugin('Signature', $format);
        if ($format === false) {
            return false;
        }

        $params = $format::load($signature);
        if ($params === false || count($params) != 2) {
            return false;
        }
        extract($params);

        if (empty($this->y)) {
            if (empty($this->x)) {
                throw new NoKeyLoadedException('No key has been loaded');
            }
            throw new UnsupportedOperationException('A private key cannot be used to sign data');
        }

        if (empty($this->p)) {
            throw new InsufficientSetupException('DSA Prime P is not set');
        }

        if (self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods())) {
            $sig = $format != 'ASN1' ? ASN1Signature::save($r, $s) : $signature;

            $result = openssl_verify($message, $sig, $this->getPublicKey(), $this->hash->getHash());

            if ($result != -1) {
                return (bool) $result;
            }
        }

        $q_1 = $this->q->subtract(self::$one);
        if (!$r->between(self::$one, $q_1) || !$s->between(self::$one, $q_1)) {
            return false;
        }

        $w = $s->modInverse($this->q);
        $h = $this->hash->hash($message);
        $h = $this->bits2int($h);
        list(, $u1) = $h->multiply($w)->divide($this->q);
        list(, $u2) = $r->multiply($w)->divide($this->q);
        $v1 = $this->g->powMod($u1, $this->p);
        $v2 = $this->y->powMod($u2, $this->p);
        list(, $v) = $v1->multiply($v2)->divide($this->p);
        list(, $v) = $v->divide($this->q);

        return $v->equals($r);
    }
}