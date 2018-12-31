<?php

/**
 * Pure-PHP implementation of ECDSA.
 *
 * PHP version 5
 *
 * Here's an example of how to create signatures and verify signatures with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * extract(\phpseclib\Crypt\ECDSA::createKey());
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
 * @package   ECDSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt;

use phpseclib\Math\BigInteger;
use phpseclib\Crypt\Common\AsymmetricKey;
use phpseclib\Exception\UnsupportedCurveException;
use phpseclib\Exception\UnsupportedOperationException;
use phpseclib\Exception\UnsupportedAlgorithmException;
use phpseclib\Exception\NoKeyLoadedException;
use phpseclib\Exception\InsufficientSetupException;
use phpseclib\File\ASN1;
use phpseclib\File\ASN1\Maps\ECParameters;
use phpseclib\Crypt\ECDSA\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib\Crypt\ECDSA\Curves\Ed25519;
use phpseclib\Crypt\ECDSA\Curves\Ed448;
use phpseclib\Crypt\ECDSA\Keys\PKCS1;
use phpseclib\Crypt\ECDSA\Keys\PKCS8;
use phpseclib\Crypt\ECDSA\Signature\ASN1 as ASN1Signature;

/**
 * Pure-PHP implementation of ECDSA.
 *
 * @package ECDSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class ECDSA extends AsymmetricKey
{
    /**
     * Algorithm Name
     *
     * @var string
     * @access private
     */
    const ALGORITHM = 'ECDSA';

    /**
     * Private Key dA
     *
     * sign() converts this to a BigInteger so one might wonder why this is a FiniteFieldInteger instead of
     * a BigInteger. That's because a FiniteFieldInteger, when converted to a byte string, is null padded by
     * a certain amount whereas a BigInteger isn't.
     *
     * @var object
     */
    private $dA;

    /**
     * Public Key QA
     *
     * @var object[]
     */
    private $QA;

    /**
     * Curve
     *
     * @var \phpseclib\Crypt\ECDSA\BaseCurves\Base
     */
    private $curve;

    /**
     * Curve Name
     *
     * @var string
     */
    private $curveName;

    /**
     * Curve Order
     *
     * Used for deterministic ECDSA
     *
     * @var \phpseclib\Math\BigInteger
     */
    protected $q;

    /**
     * Alias for the private key
     *
     * Used for deterministic ECDSA. AsymmetricKey expects $x. I don't like x because
     * with x you have x * the base point yielding an (x, y)-coordinate that is the
     * public key. But the x is different depending on which side of the equal sign
     * you're on. It's less ambiguous if you do dA * base point = (x, y)-coordinate.
     *
     * @var \phpseclib\Math\BigInteger
     */
    protected $x;

    /**
     * Alias for the private key
     *
     * Used for deterministic ECDSA. AsymmetricKey expects $x. I don't like x because
     * with x you have x * the base point yielding an (x, y)-coordinate that is the
     * public key. But the x is different depending on which side of the equal sign
     * you're on. It's less ambiguous if you do dA * base point = (x, y)-coordinate.
     *
     * @var \phpseclib\Math\BigInteger
     */
    private $context;

    /**
     * Create public / private key pair.
     *
     * @access public
     * @param string $curve
     * @return \phpseclib\Crypt\ECDSA[]
     */
    public static function createKey($curve)
    {
        self::initialize_static_variables();

        if (!isset(self::$engines['PHP'])) {
            self::useBestEngine();
        }

        if (self::$engines['libsodium'] && $curve == 'Ed25519' && function_exists('sodium_crypto_sign_keypair')) {
            $kp = sodium_crypto_sign_keypair();

            $privatekey = new static();
            $privatekey->load(sodium_crypto_sign_secretkey($kp));

            $publickey = new static();
            $publickey->load(sodium_crypto_sign_publickey($kp));

            $publickey->curveName = $privatekey->curveName = $curve;

            return compact('privatekey', 'publickey');
        }

        $privatekey = new static();

        $curveName = $curve;
        $curve = '\phpseclib\Crypt\ECDSA\Curves\\' . $curve;
        if (!class_exists($curve)) {
            throw new UnsupportedCurveException('Named Curve of ' . $curve . ' is not supported');
        }
        $curve = new $curve();
        $privatekey->dA = $dA = $curve->createRandomMultiplier();
        $privatekey->QA = $curve->multiplyPoint($curve->getBasePoint(), $dA);
        $privatekey->curve = $curve;

        $publickey = clone $privatekey;
        unset($publickey->dA);
        unset($publickey->x);

        $publickey->curveName = $privatekey->curveName = $curveName;

        return compact('privatekey', 'publickey');
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
        self::initialize_static_variables();

        if (!isset(self::$engines['PHP'])) {
            self::useBestEngine();
        }

        if ($key instanceof ECDSA) {
            $this->privateKeyFormat = $key->privateKeyFormat;
            $this->publicKeyFormat = $key->publicKeyFormat;
            $this->format = $key->format;
            $this->dA = isset($key->dA) ? $key->dA : null;
            $this->QA = $key->QA;
            $this->curve = $key->curve;
            $this->parametersFormat = $key->parametersFormat;
            $this->hash = $key->hash;

            parent::load($key, false);

            return true;
        }

        $components = parent::load($key, $type);
        if ($components === false) {
            $this->clearKey();
            return false;
        }

        if ($components['curve'] instanceof Ed25519 && $this->hashManuallySet && $this->hash->getHash() != 'sha512') {
            $this->clearKey();
            throw new UnsupportedAlgorithmException('Ed25519 only supports sha512 as a hash');
        }
        if ($components['curve'] instanceof Ed448 && $this->hashManuallySet && $this->hash->getHash() != 'shake256-912') {
            $this->clearKey();
            throw new UnsupportedAlgorithmException('Ed448 only supports shake256 with a length of 114 bytes');
        }

        $this->curve = $components['curve'];
        $this->QA = $components['QA'];
        $this->dA = isset($components['dA']) ? $components['dA'] : null;

        return true;
    }

    /**
     * Removes a key
     *
     * @access private
     */
    private function clearKey()
    {
        $this->format = null;
        $this->dA = null;
        $this->QA = null;
        $this->curve = null;
    }

    /**
     * Returns the curve
     *
     * Returns a string if it's a named curve, an array if not
     *
     * @access public
     * @return string|array
     */
    public function getCurve()
    {
        if ($this->curveName) {
            return $this->curveName;
        }

        if ($this->curve instanceof TwistedEdwardsCurve) {
            $this->curveName = $this->curve instanceof Ed25519 ? 'Ed25519' : 'Ed448';
            return $this->curveName;
        }

        $namedCurves = PKCS1::isUsingNamedCurves();
        PKCS1::useNamedCurve();

        $params = $this->getParameters();
        $decoded = ASN1::extractBER($params);
        $decoded = ASN1::decodeBER($decoded);
        $decoded = ASN1::asn1map($decoded[0], ECParameters::MAP);
        if (isset($decoded['namedCurve'])) {
            $this->curveName = $decoded['namedCurve'];

            if (!$namedCurves) {
                PKCS1::useSpecifiedCurve();
            }

            return $decoded['namedCurve'];
        }

        if (!$namedCurves) {
            PKCS1::useSpecifiedCurve();
        }

        return $decoded;
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
     *
     * @access public
     * @return int
     */
    public function getLength()
    {
        if (!isset($this->QA)) {
            return 0;
        }

        return $this->curve->getLength();
    }

    /**
     * Is the key a private key?
     *
     * @access public
     * @return bool
     */
    public function isPrivateKey()
    {
        return isset($this->dA);
    }

    /**
     * Is the key a public key?
     *
     * @access public
     * @return bool
     */
    public function isPublicKey()
    {
        return isset($this->QA);
    }

    /**
     * Returns the private key
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

        if (!isset($this->dA)) {
            return false;
        }

        return $type::savePrivateKey($this->dA, $this->curve, $this->QA, $this->password);
    }

    /**
     * Returns the public key
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

        if (!isset($this->QA)) {
            return false;
        }

        $key = $type::savePublicKey($this->curve, $this->QA);
        if ($returnObj) {
            $public = clone $this;
            $public->load($key, 'PKCS8');

            return $public;
        }
        return $key;
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

        if (!isset($this->curve) || $this->curve instanceof TwistedEdwardsCurve) {
            return false;
        }

        return $type::saveParameters($this->curve);
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
        if (!isset($this->curve)) {
            throw new InsufficientSetupException('getEngine should not be called until after a key has been loaded');
        }

        if ($this->curve instanceof TwistedEdwardsCurve) {
            return $this->curve instanceof Ed25519 && self::$engines['libsodium'] && !isset($this->context) ?
                'libsodium' : 'PHP';
        }

        return self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods()) ?
            'OpenSSL' : 'PHP';
    }

    /**
     * Sets the context
     *
     * Used by Ed25519 / Ed448.
     *
     * @see self::sign()
     * @see self::verify()
     * @access public
     * @param string $context optional
     */
    public function setContext($context = null)
    {
        if (!isset($context)) {
            $this->context = null;
            return;
        }
        if (!is_string($context)) {
            throw new \InvalidArgumentException('setContext expects a string');
        }
        if (strlen($context) > 255) {
            throw new \LengthException('The context is supposed to be, at most, 255 bytes long');
        }
        $this->context = $context;
    }

    /**
     * Determines which hashing function should be used
     *
     * @access public
     * @param string $hash
     */
    public function setHash($hash)
    {
        if ($this->curve instanceof Ed25519 && $this->hash != 'sha512') {
            throw new UnsupportedAlgorithmException('Ed25519 only supports sha512 as a hash');
        }
        if ($this->curve instanceof Ed448 && $this->hash != 'shake256-912') {
            throw new UnsupportedAlgorithmException('Ed448 only supports shake256 with a length of 114 bytes');
        }

        parent::setHash($hash);
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
        if (!isset($this->dA)) {
            if (!isset($this->QA)) {
                throw new NoKeyLoadedException('No key has been loaded');
            }
            throw new UnsupportedOperationException('A public key cannot be used to sign data');
        }

        $dA = $this->dA->toBigInteger();

        $order = $this->curve->getOrder();

        if ($this->curve instanceof TwistedEdwardsCurve) {
            if ($this->curve instanceof Ed25519 && self::$engines['libsodium'] && !isset($this->context)) {
                return sodium_crypto_sign_detached($message, $this->getPrivateKey('libsodium'));
            }

            // contexts (Ed25519ctx) are supported but prehashing (Ed25519ph) is not.
            // quoting https://tools.ietf.org/html/rfc8032#section-8.5 ,
            // "The Ed25519ph and Ed448ph variants ... SHOULD NOT be used"
            $A = $this->curve->encodePoint($this->QA);
            $curve = $this->curve;
            $hash = new Hash($curve::HASH);

            $secret = substr($hash->hash($this->dA->secret), $curve::SIZE);

            if ($curve instanceof Ed25519) {
                $dom = !isset($this->context) ? '' :
                    'SigEd25519 no Ed25519 collisions' . "\0" . chr(strlen($this->context)) . $this->context;
            } else {
                $context = isset($this->context) ? $this->context : '';
                $dom = 'SigEd448' . "\0" . chr(strlen($context)) . $context;
            }
            // SHA-512(dom2(F, C) || prefix || PH(M))
            $r = $hash->hash($dom . $secret . $message);
            $r = strrev($r);
            $r = new BigInteger($r, 256);
            list(, $r) = $r->divide($order);
            $R = $curve->multiplyPoint($curve->getBasePoint(), $curve->convertInteger($r));
            $R = $curve->encodePoint($R);
            $k = $hash->hash($dom . $R . $A . $message);
            $k = strrev($k);
            $k = new BigInteger($k, 256);
            list(, $k) = $k->divide($order);
            $S = $k->multiply($dA)->add($r);
            list(, $S) = $S->divide($order);
            $S = str_pad(strrev($S->toBytes()), $curve::SIZE, "\0");
            return $R . $S;
        }

        $shortFormat = $format;
        $format = self::validatePlugin('Signature', $format);
        if ($format === false) {
            return false;
        }

        if (self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods())) {
            $namedCurves = PKCS8::isUsingNamedCurves();

            // use specified curves to avoid issues with OpenSSL possibly not supporting a given named curve;
            // doing this may mean some curve-specific optimizations can't be used but idk if OpenSSL even
            // has curve-specific optimizations
            PKCS8::useSpecifiedCurve();

            $signature = '';
            // altho PHP's OpenSSL bindings only supported ECDSA key creation in PHP 7.1 they've long
            // supported signing / verification
            $result = openssl_sign($message, $signature, $this->getPrivateKey(), $this->hash->getHash());

            if ($namedCurves) {
                PKCS8::useNamedCurve();
            }

            if ($result) {
                if ($shortFormat == 'ASN1') {
                    return $signature;
                }

                extract(ASN1Signature::load($signature));

                return $shortFormat == 'SSH2' ? $format::save($r, $s, $this->getCurve()) : $format::save($r, $s);
            }
        }

        $e = $this->hash->hash($message);
        $e = new BigInteger($e, 256);

        $Ln = $this->hash->getLength() - $order->getLength();
        $z = $Ln > 0 ? $e->bitwise_rightShift($Ln) : $e;

        while (true) {
            $k = BigInteger::randomRange(self::$one, $order->subtract(self::$one));
            list($x, $y) = $this->curve->multiplyPoint($this->curve->getBasePoint(), $this->curve->convertInteger($k));
            $x = $x->toBigInteger();
            list(, $r) = $x->divide($order);
            if ($r->equals(self::$zero)) {
                continue;
            }
            $kinv = $k->modInverse($order);
            $temp = $z->add($dA->multiply($r));
            $temp = $kinv->multiply($temp);
            list(, $s) = $temp->divide($order);
            if (!$s->equals(self::$zero)) {
                break;
            }
        }

        // the following is an RFC6979 compliant implementation of deterministic ECDSA
        // it's unused because it's mainly intended for use when a good CSPRNG isn't
        // available. if phpseclib's CSPRNG isn't good then even key generation is
        // suspect
        /*
        // if this were actually being used it'd probably be better if this lived in load() and createKey()
        $this->q = $this->curve->getOrder();
        $dA = $this->dA->toBigInteger();
        $this->x = $dA;

        $h1 = $this->hash->hash($message);
        $k = $this->computek($h1);
        list($x, $y) = $this->curve->multiplyPoint($this->curve->getBasePoint(), $this->curve->convertInteger($k));
        $x = $x->toBigInteger();
        list(, $r) = $x->divide($this->q);
        $kinv = $k->modInverse($this->q);
        $h1 = $this->bits2int($h1);
        $temp = $h1->add($dA->multiply($r));
        $temp = $kinv->multiply($temp);
        list(, $s) = $temp->divide($this->q);
        */

        return $shortFormat == 'SSH2' ? $format::save($r, $s, $this->getCurve()) : $format::save($r, $s);
    }

    /**
     * Verify a signature
     *
     * @see self::verify()
     * @access public
     * @param string $message
     * @param string $format optional
     * @return mixed
     */
    public function verify($message, $signature, $format = 'ASN1')
    {
        if (!isset($this->QA)) {
            if (!isset($this->dA)) {
                throw new NoKeyLoadedException('No key has been loaded');
            }
            throw new UnsupportedOperationException('A private key cannot be used to verify data');
        }

        $order = $this->curve->getOrder();

        if ($this->curve instanceof TwistedEdwardsCurve) {
            if ($this->curve instanceof Ed25519 && self::$engines['libsodium'] && !isset($this->context)) {
                return sodium_crypto_sign_verify_detached($signature, $message, $this->getPublicKey('libsodium'));
            }

            $curve = $this->curve;
            if (strlen($signature) != 2 * $curve::SIZE) {
                return false;
            }

            $R = substr($signature, 0, $curve::SIZE);
            $S = substr($signature, $curve::SIZE);

            try {
                $R = PKCS1::extractPoint($R, $curve);
                $R = $this->curve->convertToInternal($R);
            } catch (\Exception $e) {
                return false;
            }

            $S = strrev($S);
            $S = new BigInteger($S, 256);

            if ($S->compare($order) >= 0) {
                return false;
            }

            $A = $curve->encodePoint($this->QA);

            if ($curve instanceof Ed25519) {
                $dom2 = !isset($this->context) ? '' :
                    'SigEd25519 no Ed25519 collisions' . "\0" . chr(strlen($this->context)) . $this->context;
            } else {
                $context = isset($this->context) ? $this->context : '';
                $dom2 = 'SigEd448' . "\0" . chr(strlen($context)) . $context;
            }

            $hash = new Hash($curve::HASH);
            $k = $hash->hash($dom2 . substr($signature, 0, $curve::SIZE) . $A . $message);
            $k = strrev($k);
            $k = new BigInteger($k, 256);
            list(, $k) = $k->divide($order);

            $qa = $curve->convertToInternal($this->QA);

            $lhs = $curve->multiplyPoint($curve->getBasePoint(), $curve->convertInteger($S));
            $rhs = $curve->multiplyPoint($qa, $curve->convertInteger($k));
            $rhs = $curve->addPoint($rhs, $R);
            $rhs = $curve->convertToAffine($rhs);

            return $lhs[0]->equals($rhs[0]) && $lhs[1]->equals($rhs[1]);
        }

        $format = self::validatePlugin('Signature', $format);
        if ($format === false) {
            return false;
        }

        $params = $format::load($signature);
        if ($params === false || count($params) != 2) {
            return false;
        }
        extract($params);

        if (self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods())) {
            $namedCurves = PKCS8::isUsingNamedCurves();

            PKCS8::useSpecifiedCurve();

            $sig = $format != 'ASN1' ? ASN1Signature::save($r, $s) : $signature;

            $result = openssl_verify($message, $sig, $this->getPublicKey(), $this->hash->getHash());

            if ($namedCurves) {
                PKCS8::useNamedCurve();
            }

            if ($result != -1) {
                return (bool) $result;
            }
        }

        $n_1 = $order->subtract(self::$one);
        if (!$r->between(self::$one, $n_1) || !$s->between(self::$one, $n_1)) {
            return false;
        }

        $e = $this->hash->hash($message);
        $e = new BigInteger($e, 256);

        $Ln = $this->hash->getLength() - $order->getLength();
        $z = $Ln > 0 ? $e->bitwise_rightShift($Ln) : $e;

        $w = $s->modInverse($order);
        list(, $u1) = $z->multiply($w)->divide($order);
        list(, $u2) = $r->multiply($w)->divide($order);

        $u1 = $this->curve->convertInteger($u1);
        $u2 = $this->curve->convertInteger($u2);

        list($x1, $y1) = $this->curve->multiplyAddPoints(
            [$this->curve->getBasePoint(), $this->QA],
            [$u1, $u2]
        );

        $x1 = $x1->toBigInteger();
        list(, $x1) = $x1->divide($order);

        return $x1->equals($r);
    }
}