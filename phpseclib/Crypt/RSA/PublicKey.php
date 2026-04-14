<?php

/**
 * RSA Public Key
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\RSA;

use phpseclib4\Crypt\{Common, RSA, Random};
use phpseclib4\Exception\{BadConfigurationException, KeyConstraintException, LengthException, UnsupportedAlgorithmException};
use phpseclib4\Math\BigInteger;

/**
 * Raw RSA Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
final class PublicKey extends RSA implements Common\PublicKey
{
    use Common\Traits\Fingerprint;

    private static bool $oidsLoaded = false;

    /**
     * Exponentiate
     */
    private function exponentiate(BigInteger $x): BigInteger
    {
        return $x->modPow($this->exponent, $this->modulus);
    }

    /**
     * RSAVP1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.2.2 RFC3447#section-5.2.2}.
     */
    private function rsavp1(BigInteger $s): BigInteger
    {
        if ($s->compare(self::$zero) < 0 || $s->compare($this->modulus) > 0) {
            throw new LengthException('Signature representative out of range');
        }
        return $this->exponentiate($s);
    }

    /**
     * RSASSA-PKCS1-V1_5-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.2.2 RFC3447#section-8.2.2}.
     */
    private function rsassa_pkcs1_v1_5_verify(string $m, string $s): bool
    {
        // Length checking

        if (strlen($s) != $this->k) {
            return false;
        }

        // RSA verification

        try {
            $s = $this->os2ip($s);
            $m2 = $this->rsavp1($s);
            $em = $this->i2osp($m2, $this->k);
        } catch (\Exception) {
            return false;
        }

        // EMSA-PKCS1-v1_5 encoding

        $exception = false;

        // If the encoding operation outputs "intended encoded message length too short," output "RSA modulus
        // too short" and stop.
        try {
            $em2 = $this->emsa_pkcs1_v1_5_encode($m, $this->k);
            $r1 = hash_equals($em, $em2);
        } catch (LengthException $e) {
            $exception = true;
        }

        try {
            $em3 = $this->emsa_pkcs1_v1_5_encode_without_null($m, $this->k);
            $r2 = hash_equals($em, $em3);
        } catch (LengthException $e) {
            $exception = true;
        } catch (UnsupportedAlgorithmException $e) {
            $r2 = false;
        }

        if ($exception) {
            throw new KeyConstraintException('RSA modulus too short');
        }

        // Compare
        return boolval($r1 | $r2);
    }

    /**
     * EMSA-PSS-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.1.2 RFC3447#section-9.1.2}.
     */
    private function emsa_pss_verify(string $m, string $em, int $emBits): bool
    {
        // if $m is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        $emLen = ($emBits + 7) >> 3; // ie. ceil($emBits / 8);
        $sLen = $this->sLen ?? $this->hLen;

        $mHash = $this->hash->hash($m);
        if ($emLen < $this->hLen + $sLen + 2) {
            return false;
        }

        if ($em[-1] != chr(0xBC)) {
            return false;
        }

        $maskedDB = substr($em, 0, -$this->hLen - 1);
        $h = substr($em, -$this->hLen - 1, $this->hLen);
        $temp = chr(256 - (1 << ($emBits & 7)));
        if ((~$maskedDB[0] & $temp) != $temp) {
            return false;
        }
        $dbMask = $this->mgf1($h, $emLen - $this->hLen - 1);
        $db = $maskedDB ^ $dbMask;
        $db[0] = ~chr(256 - (1 << ($emBits & 7))) & $db[0];
        $temp = $emLen - $this->hLen - $sLen - 2;
        if (substr($db, 0, $temp) != str_repeat(chr(0), $temp) || ord($db[$temp]) != 1) {
            return false;
        }
        $salt = substr($db, $temp + 1); // should be $sLen long
        $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
        $h2 = $this->hash->hash($m2);
        return hash_equals($h, $h2);
    }

    /**
     * RSASSA-PSS-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.1.2 RFC3447#section-8.1.2}.
     */
    private function rsassa_pss_verify(string $m, string $s): bool
    {
        // Length checking

        if (strlen($s) != $this->k) {
            return false;
        }

        // RSA verification

        $modBits = strlen($this->modulus->toBits());

        try {
            $s2 = $this->os2ip($s);
            $m2 = $this->rsavp1($s2);
            $em = $this->i2osp($m2, $this->k);
        } catch (\Exception) {
            return false;
        }

        // EMSA-PSS verification

        return $this->emsa_pss_verify($m, $em, $modBits - 1);
    }

    /**
     * Verifies a signature
     *
     * @see self::sign()
     */
    public function verify(string $message, string $signature): bool
    {
        /*
        https://datatracker.ietf.org/doc/html/rfc4055#page-6 says the following:

           There are two possible encodings for the AlgorithmIdentifier
           parameters field associated with these object identifiers.  The two
           alternatives arise from the loss of the OPTIONAL associated with the
           algorithm identifier parameters when the 1988 syntax for
           AlgorithmIdentifier was translated into the 1997 syntax.  Later the
           OPTIONAL was recovered via a defect report, but by then many people
           thought that algorithm parameters were mandatory.  Because of this
           history some implementations encode parameters as a NULL element
           while others omit them entirely.  The correct encoding is to omit the
           parameters field; however, when RSASSA-PSS and RSAES-OAEP were
           defined, it was done using the NULL parameters rather than absent
           parameters.

           All implementations MUST accept both NULL and absent parameters as
           legal and equivalent encodings.

        OpenSSL does NOT accept both - it REQUIRES NULL be present. phpseclib, however,
        DOES accept both. at first, it didn't. at first, not knowing why some small number
        of PKCS1 signatures ommitted NULL, i added the SIGNATURE_RELAXED_PKCS1 mode on
        2015-08-26. https://phpseclib.com/docs/rsa#rsasignature_relaxed_pkcs1 talks more
        about that mode. later, on 2021-04-05, there was CVE-2021-30130. consequently,
        the SIGNATURE_PKCS1 mode was updated to accept either NULL or non-NULL.

        because phpseclib accepts PKCS1 signatures that OpenSSL doesn't, OpenSSL isn't
        used for PKCS1. if the OpenSSL extension is installed then it'll be used to perform
        unpadded RSA (ie. modular exponentation), however, the actual PKCS1 construction
        takes place in PHP code vs OpenSSL.

        see https://security.stackexchange.com/questions/110330/encoding-of-optional-null-in-der
        for an additional reference
        */
        if ($this->signaturePadding === self::SIGNATURE_PKCS1 && isset(self::$forcedEngine) && self::$forcedEngine !== 'PHP') {
            throw new BadConfigurationException('Engine OpenSSL is forced but unavailable for RSA PKCS1 signature verification');
        }

        $result = $this->handleOpenSSL('openssl_verify', $message, $signature);
        if ($result !== null) {
            return $result;
        }

        return match ($this->signaturePadding) {
            self::SIGNATURE_PKCS1 => $this->rsassa_pkcs1_v1_5_verify($message, $signature),
            self::SIGNATURE_PSS => $this->rsassa_pss_verify($message, $signature)
        };
    }

    /**
     * RSAES-PKCS1-V1_5-ENCRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.2.1 RFC3447#section-7.2.1}.
     */
    private function rsaes_pkcs1_v1_5_encrypt(string $m, bool $pkcs15_compat = false): string
    {
        $mLen = strlen($m);

        // Length checking

        if ($mLen > $this->k - 11) {
            throw new KeyConstraintException('Message too long');
        }

        // EME-PKCS1-v1_5 encoding

        $psLen = $this->k - $mLen - 3;
        $ps = '';
        while (strlen($ps) != $psLen) {
            $temp = Random::string($psLen - strlen($ps));
            $temp = str_replace("\x00", '', $temp);
            $ps .= $temp;
        }
        $type = 2;
        $em = chr(0) . chr($type) . $ps . chr(0) . $m;

        // RSA encryption
        $m = $this->os2ip($em);
        $c = $this->rsaep($m);
        $c = $this->i2osp($c, $this->k);

        // Output the ciphertext C

        return $c;
    }

    /**
     * RSAES-OAEP-ENCRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.1.1 RFC3447#section-7.1.1} and
     * {http://en.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding OAES}.
     */
    private function rsaes_oaep_encrypt(string $m): string
    {
        $mLen = strlen($m);

        // Length checking

        // if $l is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        if ($mLen > $this->k - 2 * $this->hLen - 2) {
            throw new KeyConstraintException('Message too long');
        }

        // EME-OAEP encoding

        $lHash = $this->hash->hash($this->label);
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
     * RSAEP
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.1 RFC3447#section-5.1.1}.
     */
    private function rsaep(BigInteger $m): BigInteger
    {
        if ($m->compare(self::$zero) < 0 || $m->compare($this->modulus) > 0) {
            throw new LengthException('Message representative out of range');
        }
        return $this->exponentiate($m);
    }

    /**
     * Raw Encryption / Decryption
     *
     * Doesn't use padding and is not recommended.
     */
    private function raw_encrypt(string $m): string
    {
        if (strlen($m) > $this->k) {
            throw new KeyConstraintException('Message too long');
        }

        $temp = $this->os2ip($m);
        $temp = $this->rsaep($temp);
        return  $this->i2osp($temp, $this->k);
    }

    /**
     * Encryption
     *
     * Both self::PADDING_OAEP and self::PADDING_PKCS1 both place limits on how long $plaintext can be.
     * If $plaintext exceeds those limits it will be broken up so that it does and the resultant ciphertext's will
     * be concatenated together.
     *
     * @see self::decrypt()
     */
    public function encrypt(string $plaintext): string
    {
        $result = $this->handleOpenSSL('openssl_public_encrypt', $plaintext);
        if ($result !== null) {
            return $result;
        }

        return match ($this->encryptionPadding) {
            self::ENCRYPTION_NONE => $this->raw_encrypt($plaintext),
            self::ENCRYPTION_PKCS1 => $this->rsaes_pkcs1_v1_5_encrypt($plaintext),
            // self::ENCRYPTION_OAEP
            default => $this->rsaes_oaep_encrypt($plaintext)
        };
    }

    /**
     * Converts a public key to a private key
     */
    public function asPrivateKey(): RSA
    {
        $new = new PrivateKey();
        $new->exponent = $this->exponent;
        $new->modulus = $this->modulus;
        $new->k = $this->k;
        $new->format = $this->format;
        return $new
            ->withHash($this->hash->getHash())
            ->withMGFHash($this->mgfHash->getHash())
            ->withSaltLength($this->sLen)
            ->withLabel($this->label)
            ->withPadding($this->signaturePadding | $this->encryptionPadding);
    }
}
