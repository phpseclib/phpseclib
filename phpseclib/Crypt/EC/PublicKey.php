<?php

/**
 * EC Public Key
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt\EC;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib3\Crypt\EC\Curves\Ed25519;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS1;
use phpseclib3\Crypt\EC\Formats\Signature\ASN1 as ASN1Signature;
use phpseclib3\Crypt\Hash;
use phpseclib3\Exception\BadConfigurationException;
use phpseclib3\Exception\UnsupportedOperationException;
use phpseclib3\Math\BigInteger;

/**
 * EC Public Key
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
final class PublicKey extends EC implements Common\PublicKey
{
    use Common\Traits\Fingerprint;

    /**
     * Verify a signature
     *
     * @see self::verify()
     * @param string $message
     * @param string $signature
     * @return mixed
     */
    public function verify($message, $signature)
    {
        if ($this->curve instanceof MontgomeryCurve) {
            throw new UnsupportedOperationException('Montgomery Curves cannot be used to create signatures');
        }

        $shortFormat = $this->shortFormat;
        $format = $this->sigFormat;
        if ($format === false) {
            return false;
        }

        if (self::$forcedEngine === 'libsodium' && !$this->curve instanceof Ed25519) {
            throw new BadConfigurationException('Engine libsodium is only supported for Ed25519');
        }

        // at this point either self::$forcedEngine is NOT libsodium or the curve is Ed25519

        if ($this->curve instanceof Ed25519 && self::$forcedEngine !== 'PHP' && self::$forcedEngine !== 'OpenSSL') {
            if (self::$forcedEngine === 'libsodium') {
                if (!function_exists('sodium_crypto_sign_verify_detached')) {
                    throw new BadConfigurationException('Engine libsodium is forced but unsupported for Ed25519 / Ed448');
                }
                if (isset($this->context)) {
                    throw new BadConfigurationException('Engine libsodium is forced but unsupported for Ed25519ctx (context)');
                }
            }
            if (function_exists('sodium_crypto_sign_verify_detached') && !isset($this->context)) {
                if ($shortFormat == 'SSH2') {
                    list(, $signature) = Strings::unpackSSH2('ss', $signature);
                }

                return sodium_crypto_sign_verify_detached($signature, $message, $this->toString('libsodium'));
            }
        }

        // at this point self::$forcedEngine CAN'T be libsodium so we won't check for it henceforth

        if ($this->curve instanceof TwistedEdwardsCurve) {
            if ($shortFormat == 'SSH2') {
                list(, $signature) = Strings::unpackSSH2('ss', $signature);
            }

            if (self::$forcedEngine !== 'PHP') {
                $keyTypeConstant = $this->curve instanceof Ed25519 ? 'OPENSSL_KEYTYPE_ED25519' : 'OPENSSL_KEYTYPE_ED448';
                if (self::$forcedEngine === 'OpenSSL') {
                    if (!defined($keyTypeConstant)) {
                        throw new BadConfigurationException('Engine OpenSSL is forced but unsupported for Ed25519 / Ed448');
                    }
                    // OpenSSL supports Ed25519/Ed448 but not Ed25519ctx (context), so skip if context is set
                    if (isset($this->context)) {
                        throw new BadConfigurationException('Engine OpenSSL is forced but unsupported for Ed25519 / Ed448 curves with context\'s');
                    }
                }
                if (defined($keyTypeConstant) && !isset($this->context)) {
                    // algorithm 0 is used because EdDSA has a built-in hash
                    $result = openssl_verify($message, $signature, $this->toString('PKCS8'), 0) === 1;
                    if ($result !== -1 && $result !== false) {
                        return (bool) $result;
                    }
                    if (self::$forcedEngine === 'OpenSSL') {
                        throw new BadConfigurationException('Engine OpenSSL is forced but was unable to create signature because of ' . openssl_error_string());
                    }
                }
            }

            $order = $this->curve->getOrder();

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

            $lhs = $curve->multiplyPoint($curve->getBasePoint(), $S);
            $rhs = $curve->multiplyPoint($qa, $k);
            $rhs = $curve->addPoint($rhs, $R);
            $rhs = $curve->convertToAffine($rhs);

            return $lhs[0]->equals($rhs[0]) && $lhs[1]->equals($rhs[1]);
        }

        $params = $format::load($signature);
        if ($params === false || count($params) != 2) {
            return false;
        }
        $r = $params['r'];
        $s = $params['s'];

        if (self::$forcedEngine === 'OpenSSL' && !function_exists('openssl_get_md_methods')) {
            throw new BadConfigurationException('Engine OpenSSL is forced but unsupported for ECDSA');
        }

        // at this point $forcedEngine is either PHP or null. either that OR openssl_get_md_methods() exists

        if (self::$forcedEngine !== 'PHP') {
            if (in_array($this->hash->getHash(), openssl_get_md_methods())) {
                $sig = $format != 'ASN1' ? ASN1Signature::save($r, $s) : $signature;

                $result = openssl_verify($message, $sig, $this->toString('PKCS8', ['namedCurve' => false]), $this->hash->getHash());

                if ($result !== -1 && $result !== false) {
                    return (bool) $result;
                }
                if (self::$forcedEngine === 'OpenSSL') {
                    throw new BadConfigurationException('Engine OpenSSL is forced but was unable to verify signature because of ' . openssl_error_string());
                }
            } elseif (self::$forcedEngine === 'OpenSSL') {
                throw new BadConfigurationException('Engine OpenSSL is forced but unsupported for ECDSA / ' . $this->hash->getHash());
            }
        }

        $order = $this->curve->getOrder();

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

    /**
     * Returns the public key
     *
     * @param string $type
     * @param array $options optional
     * @return string
     */
    public function toString($type, array $options = [])
    {
        $type = self::validatePlugin('Keys', $type, 'savePublicKey');

        return $type::savePublicKey($this->curve, $this->QA, $options);
    }
}
