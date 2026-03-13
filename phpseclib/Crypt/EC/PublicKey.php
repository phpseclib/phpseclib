<?php

/**
 * EC Public Key
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\EC;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\Common;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib4\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib4\Crypt\EC\Curves\Ed25519;
use phpseclib4\Crypt\EC\Formats\Keys\PKCS1;
use phpseclib4\Crypt\EC\Formats\Signature\ASN1 as ASN1Signature;
use phpseclib4\Crypt\Hash;
use phpseclib4\Exception\UnsupportedOperationException;
use phpseclib4\Math\BigInteger;

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
     */
    public function verify(string $message, string $signature): bool
    {
        if ($this->curve instanceof MontgomeryCurve) {
            throw new UnsupportedOperationException('Montgomery Curves cannot be used to create signatures');
        }

        $shortFormat = $this->shortFormat;
        $format = $this->sigFormat;
        if ($format === false) {
            return false;
        }

        $order = $this->curve->getOrder();

        if ($this->curve instanceof TwistedEdwardsCurve) {
            if ($shortFormat == 'SSH2') {
                [, $signature] = Strings::unpackSSH2('ss', $signature);
            }

            // OpenSSL supports Ed25519/Ed448 but not Ed25519ctx (context), so skip if context is set
            if (self::$engines['OpenSSL'] && !isset($this->context)) {
                $keyTypeConstant = $this->curve instanceof Ed25519 ? 'OPENSSL_KEYTYPE_ED25519' : 'OPENSSL_KEYTYPE_ED448';
                if (defined($keyTypeConstant)) {
                    // algorithm 0 is used because EdDSA has a built-in hash
                    return openssl_verify($message, $signature, $this->toString('PKCS8'), 0) === 1;
                }
            }

            if ($this->curve instanceof Ed25519 && self::$engines['libsodium'] && !isset($this->context)) {
                return sodium_crypto_sign_verify_detached($signature, $message, $this->toString('libsodium'));
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
                $context = $this->context ?? '';
                $dom2 = 'SigEd448' . "\0" . chr(strlen($context)) . $context;
            }

            $hash = new Hash($curve::HASH);
            $k = $hash->hash($dom2 . substr($signature, 0, $curve::SIZE) . $A . $message);
            $k = strrev($k);
            $k = new BigInteger($k, 256);
            [, $k] = $k->divide($order);

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
        ['r' => $r, 's' => $s] = $params;

        if (self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods())) {
            $sig = $format != 'ASN1' ? ASN1Signature::save($r, $s) : $signature;

            $result = openssl_verify($message, $sig, $this->toString('PKCS8', ['namedCurve' => false]), $this->hash->getHash());

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
        [, $u1] = $z->multiply($w)->divide($order);
        [, $u2] = $r->multiply($w)->divide($order);

        $u1 = $this->curve->convertInteger($u1);
        $u2 = $this->curve->convertInteger($u2);

        [$x1, $y1] = $this->curve->multiplyAddPoints(
            [$this->curve->getBasePoint(), $this->QA],
            [$u1, $u2]
        );

        $x1 = $x1->toBigInteger();
        [, $x1] = $x1->divide($order);

        return $x1->equals($r);
    }

    /**
     * Returns the public key
     *
     * @param array $options optional
     */
    public function toString(string $type, array $options = []): string
    {
        $type = self::validatePlugin('Keys', $type, 'savePublicKey');

        return $type::savePublicKey($this->curve, $this->QA, $options);
    }
}
