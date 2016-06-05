<?php
/**
 * PKCS#8 Formatted RSA Key Handler
 *
 * PHP version 5
 *
 * Used by PHP's openssl_public_encrypt() and openssl's rsautl (when -pubin is set)
 *
 * Has the following header:
 *
 * -----BEGIN PUBLIC KEY-----
 *
 * Analogous to ssh-keygen's pkcs8 format (as specified by -m). Although PKCS8
 * is specific to private keys it's basically creating a DER-encoded wrapper
 * for keys. This just extends that same concept to public keys (much like ssh-keygen)
 *
 * @category  Crypt
 * @package   RSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\RSA;

use ParagonIE\ConstantTime\Base64;
use phpseclib\Crypt\DES;
use phpseclib\Crypt\Random;
use phpseclib\Math\BigInteger;

/**
 * PKCS#8 Formatted RSA Key Handler
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class PKCS8 extends PKCS
{
    /**
     * Convert a private key to the appropriate format.
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $n
     * @param \phpseclib\Math\BigInteger $e
     * @param \phpseclib\Math\BigInteger $d
     * @param array $primes
     * @param array $exponents
     * @param array $coefficients
     * @param string $password optional
     * @return string
     */
    static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, $primes, $exponents, $coefficients, $password = '')
    {
        $num_primes = count($primes);
        $raw = array(
            'version' => $num_primes == 2 ? chr(0) : chr(1), // two-prime vs. multi
            'modulus' => $n->toBytes(true),
            'publicExponent' => $e->toBytes(true),
            'privateExponent' => $d->toBytes(true),
            'prime1' => $primes[1]->toBytes(true),
            'prime2' => $primes[2]->toBytes(true),
            'exponent1' => $exponents[1]->toBytes(true),
            'exponent2' => $exponents[2]->toBytes(true),
            'coefficient' => $coefficients[2]->toBytes(true)
        );

        $components = array();
        foreach ($raw as $name => $value) {
            $components[$name] = pack('Ca*a*', self::ASN1_INTEGER, self::_encodeLength(strlen($value)), $value);
        }

        $RSAPrivateKey = implode('', $components);

        if ($num_primes > 2) {
            $OtherPrimeInfos = '';
            for ($i = 3; $i <= $num_primes; $i++) {
                // OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
                //
                // OtherPrimeInfo ::= SEQUENCE {
                //     prime             INTEGER,  -- ri
                //     exponent          INTEGER,  -- di
                //     coefficient       INTEGER   -- ti
                // }
                $OtherPrimeInfo = pack('Ca*a*', self::ASN1_INTEGER, self::_encodeLength(strlen($primes[$i]->toBytes(true))), $primes[$i]->toBytes(true));
                $OtherPrimeInfo.= pack('Ca*a*', self::ASN1_INTEGER, self::_encodeLength(strlen($exponents[$i]->toBytes(true))), $exponents[$i]->toBytes(true));
                $OtherPrimeInfo.= pack('Ca*a*', self::ASN1_INTEGER, self::_encodeLength(strlen($coefficients[$i]->toBytes(true))), $coefficients[$i]->toBytes(true));
                $OtherPrimeInfos.= pack('Ca*a*', self::ASN1_SEQUENCE, self::_encodeLength(strlen($OtherPrimeInfo)), $OtherPrimeInfo);
            }
            $RSAPrivateKey.= pack('Ca*a*', self::ASN1_SEQUENCE, self::_encodeLength(strlen($OtherPrimeInfos)), $OtherPrimeInfos);
        }

        $RSAPrivateKey = pack('Ca*a*', self::ASN1_SEQUENCE, self::_encodeLength(strlen($RSAPrivateKey)), $RSAPrivateKey);

        $rsaOID = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"; // hex version of MA0GCSqGSIb3DQEBAQUA
        $RSAPrivateKey = pack(
            'Ca*a*Ca*a*',
            self::ASN1_INTEGER,
            "\01\00",
            $rsaOID,
            4,
            self::_encodeLength(strlen($RSAPrivateKey)),
            $RSAPrivateKey
        );
        $RSAPrivateKey = pack('Ca*a*', self::ASN1_SEQUENCE, self::_encodeLength(strlen($RSAPrivateKey)), $RSAPrivateKey);
        if (!empty($password) || is_string($password)) {
            $salt = Random::string(8);
            $iterationCount = 2048;

            $crypto = new DES(DES::MODE_CBC);
            $crypto->setPassword($password, 'pbkdf1', 'md5', $salt, $iterationCount);
            $RSAPrivateKey = $crypto->encrypt($RSAPrivateKey);

            $parameters = pack(
                'Ca*a*Ca*N',
                self::ASN1_OCTETSTRING,
                self::_encodeLength(strlen($salt)),
                $salt,
                self::ASN1_INTEGER,
                self::_encodeLength(4),
                $iterationCount
            );
            $pbeWithMD5AndDES_CBC = "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x03";

            $encryptionAlgorithm = pack(
                'Ca*a*Ca*a*',
                self::ASN1_OBJECT,
                self::_encodeLength(strlen($pbeWithMD5AndDES_CBC)),
                $pbeWithMD5AndDES_CBC,
                self::ASN1_SEQUENCE,
                self::_encodeLength(strlen($parameters)),
                $parameters
            );

            $RSAPrivateKey = pack(
                'Ca*a*Ca*a*',
                self::ASN1_SEQUENCE,
                self::_encodeLength(strlen($encryptionAlgorithm)),
                $encryptionAlgorithm,
                self::ASN1_OCTETSTRING,
                self::_encodeLength(strlen($RSAPrivateKey)),
                $RSAPrivateKey
            );

            $RSAPrivateKey = pack('Ca*a*', self::ASN1_SEQUENCE, self::_encodeLength(strlen($RSAPrivateKey)), $RSAPrivateKey);

            $RSAPrivateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n" .
                 chunk_split(Base64::encode($RSAPrivateKey), 64) .
                 '-----END ENCRYPTED PRIVATE KEY-----';
        } else {
            $RSAPrivateKey = "-----BEGIN PRIVATE KEY-----\r\n" .
                 chunk_split(Base64::encode($RSAPrivateKey), 64) .
                 '-----END PRIVATE KEY-----';
        }

        return $RSAPrivateKey;
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $n
     * @param \phpseclib\Math\BigInteger $e
     * @return string
     */
    static function savePublicKey(BigInteger $n, BigInteger $e)
    {
        $modulus = $n->toBytes(true);
        $publicExponent = $e->toBytes(true);

        // from <http://tools.ietf.org/html/rfc3447#appendix-A.1.1>:
        // RSAPublicKey ::= SEQUENCE {
        //     modulus           INTEGER,  -- n
        //     publicExponent    INTEGER   -- e
        // }
        $components = array(
            'modulus' => pack('Ca*a*', self::ASN1_INTEGER, self::_encodeLength(strlen($modulus)), $modulus),
            'publicExponent' => pack('Ca*a*', self::ASN1_INTEGER, self::_encodeLength(strlen($publicExponent)), $publicExponent)
        );

        $RSAPublicKey = pack(
            'Ca*a*a*',
            self::ASN1_SEQUENCE,
            self::_encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
            $components['modulus'],
            $components['publicExponent']
        );

        // sequence(oid(1.2.840.113549.1.1.1), null)) = rsaEncryption.
        $rsaOID = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"; // hex version of MA0GCSqGSIb3DQEBAQUA
        $RSAPublicKey = chr(0) . $RSAPublicKey;
        $RSAPublicKey = chr(3) . self::_encodeLength(strlen($RSAPublicKey)) . $RSAPublicKey;

        $RSAPublicKey = pack(
            'Ca*a*',
            self::ASN1_SEQUENCE,
            self::_encodeLength(strlen($rsaOID . $RSAPublicKey)),
            $rsaOID . $RSAPublicKey
        );

        $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
                        chunk_split(Base64::encode($RSAPublicKey), 64) .
                        '-----END PUBLIC KEY-----';

        return $RSAPublicKey;
    }
}
