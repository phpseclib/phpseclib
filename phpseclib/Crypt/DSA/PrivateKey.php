<?php

/**
 * DSA Private Key
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\DSA;

use phpseclib4\Crypt\{Common, DSA};
use phpseclib4\Crypt\DSA\Formats\Signature\ASN1 as ASN1Signature;
use phpseclib4\Exception\BadConfigurationException;
use phpseclib4\File\Common\Signable;
use phpseclib4\File\CSR;
use phpseclib4\Math\BigInteger;

/**
 * DSA Private Key
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
final class PrivateKey extends DSA implements Common\PrivateKey
{
    use Common\Traits\PasswordProtected;

    /**
     * DSA secret exponent x
     */
    protected BigInteger $x;

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
     */
    public function getPublicKey(): PublicKey
    {
        $type = self::validatePlugin('Keys', 'PKCS8', 'savePublicKey');

        $this->y ??= $this->g->powMod($this->x, $this->p);

        $key = $type::savePublicKey($this->p, $this->q, $this->g, $this->y);

        return DSA::loadFormat('PKCS8', $key)
            ->withHash($this->hash->getHash())
            ->withSignatureFormat($this->shortFormat);
    }

    /**
     * Create a signature
     *
     * @see self::verify()
     */
    public function sign(string|Signable $source): string
    {
        $format = $this->sigFormat;

        if (self::$forcedEngine === 'libsodium') {
            throw new BadConfigurationException('Engine libsodium is forced but unsupported for DSA');
        }

        if (self::$forcedEngine === 'OpenSSL' && !function_exists('openssl_get_md_methods')) {
            throw new BadConfigurationException('Engine OpenSSL is forced but unsupported for DSA');
        }

        if ($source instanceof Signable) {
            $public = $this->getPublicKey();
            if ($source instanceof CSR && !$source->hasPublicKey()) {
                $source->setPublicKey($public);
            }
            $source->identifySignatureAlgorithm($public);
            $message = $source->getSignableSection();
        } else {
            $message = $source;
        }

        if (function_exists('openssl_get_md_methods') && self::$forcedEngine !== 'PHP') {
            if (in_array($this->hash->getHash(), openssl_get_md_methods())) {
                $signature = '';
                $result = openssl_sign($message, $signature, $this->toString('PKCS8'), $this->hash->getHash());

                if ($result) {
                    if ($this->shortFormat == 'ASN1') {
                        if ($source instanceof Signable) {
                            $source->setSignature($signature);
                        }
                        return $signature;
                    }

                    $loaded = ASN1Signature::load($signature);
                    $r = $loaded['r'];
                    $s = $loaded['s'];

                    if ($source instanceof Signable) {
                        $source->setSignature($signature);
                    }

                    return $format::save($r, $s);
                } elseif (self::$forcedEngine === 'OpenSSL') {
                    throw new BadConfigurationException('Engine OpenSSL is forced but was unable to create signature because of ' . openssl_error_string());
                }
            } elseif (self::$forcedEngine === 'OpenSSL') {
                throw new BadConfigurationException('Engine OpenSSL is forced but unsupported for DSA / ' . $this->hash->getHash());
            }
        }

        $h = $this->hash->hash($message);
        $h = $this->bits2int($h);

        while (true) {
            $k = BigInteger::randomRange(self::$one, $this->q->subtract(self::$one));
            $r = $this->g->powMod($k, $this->p);
            [, $r] = $r->divide($this->q);
            if ($r->equals(self::$zero)) {
                continue;
            }
            $kinv = $k->modInverse($this->q);
            $temp = $h->add($this->x->multiply($r));
            $temp = $kinv->multiply($temp);
            [, $s] = $temp->divide($this->q);
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
        [, $r] = $r->divide($this->q);
        $kinv = $k->modInverse($this->q);
        $h1 = $this->bits2int($h1);
        $temp = $h1->add($this->x->multiply($r));
        $temp = $kinv->multiply($temp);
        [, $s] = $temp->divide($this->q);
        */

        $signature = $format::save($r, $s);
        if ($source instanceof Signable) {
            $source->setSignature($signature);
        }
        return $signature;
    }

    /**
     * Returns the private key as a string
     */
    public function toString(string $type, array $options = []): string
    {
        $type = self::validatePlugin('Keys', $type, 'savePrivateKey');

        $this->y ??= $this->g->powMod($this->x, $this->p);

        return $type::savePrivateKey($this->p, $this->q, $this->g, $this->y, $this->x, $this->password, $options);
    }

    public function toArray(): array
    {
        $this->y ??= $this->g->powMod($this->x, $this->p);

        return [
            'p' => clone $this->p,
            'q' => clone $this->q,
            'g' => clone $this->g,
            'y' => clone $this->y,
            'x' => clone $this->x,
        ];
    }
}
