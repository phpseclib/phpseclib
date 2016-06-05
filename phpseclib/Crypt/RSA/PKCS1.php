<?php
/**
 * PKCS#1 Formatted RSA Key Handler
 *
 * PHP version 5
 *
 * Used by File/X509.php
 *
 * Has the following header:
 *
 * -----BEGIN RSA PUBLIC KEY-----
 *
 * Analogous to ssh-keygen's pem format (as specified by -m)
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
use ParagonIE\ConstantTime\Hex;
use phpseclib\Crypt\AES;
use phpseclib\Crypt\DES;
use phpseclib\Crypt\Random;
use phpseclib\Crypt\TripleDES;
use phpseclib\Math\BigInteger;

/**
 * PKCS#1 Formatted RSA Key Handler
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class PKCS1 extends PKCS
{
    /**
     * Default encryption algorithm
     *
     * @var string
     * @access private
     */
    static $defaultEncryptionAlgorithm = 'DES-EDE3-CBC';

    /**
     * Sets the default encryption algorithm
     *
     * @access public
     * @param string $algo
     */
    static function setEncryptionAlgorithm($algo)
    {
        self::$defaultEncryptionAlgorithm = $algo;
    }

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

        if (!empty($password) || is_string($password)) {
            $cipher = self::getEncryptionObject(self::$defaultEncryptionAlgorithm);
            $iv = Random::string($cipher->getBlockLength() >> 3);
            $cipher->setKey(self::generateSymmetricKey($password, $iv, $cipher->getKeyLength() >> 3));
            $cipher->setIV($iv);
            $iv = strtoupper(Hex::encode($iv));
            $RSAPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\r\n" .
                     "Proc-Type: 4,ENCRYPTED\r\n" .
                     "DEK-Info: " . self::$defaultEncryptionAlgorithm . ",$iv\r\n" .
                     "\r\n" .
                     chunk_split(Base64::encode($cipher->encrypt($RSAPrivateKey)), 64) .
                     '-----END RSA PRIVATE KEY-----';
        } else {
            $RSAPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\r\n" .
                     chunk_split(Base64::encode($RSAPrivateKey), 64) .
                     '-----END RSA PRIVATE KEY-----';
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

        $RSAPublicKey = "-----BEGIN RSA PUBLIC KEY-----\r\n" .
                        chunk_split(Base64::encode($RSAPublicKey), 64) .
                        '-----END RSA PUBLIC KEY-----';

        return $RSAPublicKey;
    }
}
