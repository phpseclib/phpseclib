<?php

/**
 * PKCS Formatted RSA Key Handler
 *
 * PHP version 5
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
use phpseclib\Crypt\Common\BlockCipher;
use phpseclib\Crypt\AES;
use phpseclib\Crypt\Base;
use phpseclib\Crypt\DES;
use phpseclib\Crypt\TripleDES;
use phpseclib\Math\BigInteger;
use phpseclib\Common\Functions\Strings;
use phpseclib\Common\Functions\ASN1;

/**
 * PKCS Formatted RSA Key Handler
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class PKCS
{
    /**#@+
     * @access private
     * @see \phpseclib\Crypt\RSA::createKey()
     */
    /**
     * ASN1 Integer
     */
    const ASN1_INTEGER = 2;
    /**
     * ASN1 Bit String
     */
    const ASN1_BITSTRING = 3;
    /**
     * ASN1 Octet String
     */
    const ASN1_OCTETSTRING = 4;
    /**
     * ASN1 Object Identifier
     */
    const ASN1_OBJECT = 6;
    /**
     * ASN1 Sequence (with the constucted bit set)
     */
    const ASN1_SEQUENCE = 48;
    /**#@-*/

    /**#@+
     * @access private
     */
    /**
     * Auto-detect the format
     */
    const MODE_ANY = 0;
    /**
     * Require base64-encoded PEM's be supplied
     */
    const MODE_PEM = 1;
    /**
     * Require raw DER's be supplied
     */
    const MODE_DER = 2;
    /**#@-*/

    /**
     * Is the key a base-64 encoded PEM, DER or should it be auto-detected?
     *
     * @access private
     * @param int
     */
    static $format = self::MODE_ANY;

    /**
     * Returns the mode constant corresponding to the mode string
     *
     * @access public
     * @param string $mode
     * @return int
     * @throws \UnexpectedValueException if the block cipher mode is unsupported
     */
    static function getEncryptionMode($mode)
    {
        switch ($mode) {
            case 'CBC':
                return BlockCipher::MODE_CBC;
            case 'ECB':
                return BlockCipher::MODE_ECB;
            case 'CFB':
                return BlockCipher::MODE_CFB;
            case 'OFB':
                return BlockCipher::MODE_OFB;
            case 'CTR':
                return BlockCipher::MODE_CTR;
        }
        throw new \UnexpectedValueException('Unsupported block cipher mode of operation');
    }

    /**
     * Returns a cipher object corresponding to a string
     *
     * @access public
     * @param string $algo
     * @return string
     * @throws \UnexpectedValueException if the encryption algorithm is unsupported
     */
    static function getEncryptionObject($algo)
    {
        $modes = '(CBC|ECB|CFB|OFB|CTR)';
        switch (true) {
            case preg_match("#^AES-(128|192|256)-$modes$#", $algo, $matches):
                $cipher = new AES(self::getEncryptionMode($matches[2]));
                $cipher->setKeyLength($matches[1]);
                return $cipher;
            case preg_match("#^DES-EDE3-$modes$#", $algo, $matches):
                return new TripleDES(self::getEncryptionMode($matches[1]));
            case preg_match("#^DES-$modes$#", $algo, $matches):
                return new DES(self::getEncryptionMode($matches[1]));
            default:
                throw new \UnexpectedValueException('Unsupported encryption algorithmn');
        }
    }

    /**
     * Generate a symmetric key for PKCS#1 keys
     *
     * @access public
     * @param string $password
     * @param string $iv
     * @param int $length
     * @return string
     */
    static function generateSymmetricKey($password, $iv, $length)
    {
        $symkey = '';
        $iv = substr($iv, 0, 8);
        while (strlen($symkey) < $length) {
            $symkey.= md5($symkey . $password . $iv, true);
        }
        return substr($symkey, 0, $length);
    }

    /**
     * Break a public or private key down into its constituent components
     *
     * @access public
     * @param string $key
     * @param string $password optional
     * @return array
     */
    static function load($key, $password = '')
    {
        if (!is_string($key)) {
            return false;
        }

        $components = array('isPublicKey' => strpos($key, 'PUBLIC') !== false);

        /* Although PKCS#1 proposes a format that public and private keys can use, encrypting them is
           "outside the scope" of PKCS#1.  PKCS#1 then refers you to PKCS#12 and PKCS#15 if you're wanting to
           protect private keys, however, that's not what OpenSSL* does.  OpenSSL protects private keys by adding
           two new "fields" to the key - DEK-Info and Proc-Type.  These fields are discussed here:

           http://tools.ietf.org/html/rfc1421#section-4.6.1.1
           http://tools.ietf.org/html/rfc1421#section-4.6.1.3

           DES-EDE3-CBC as an algorithm, however, is not discussed anywhere, near as I can tell.
           DES-CBC and DES-EDE are discussed in RFC1423, however, DES-EDE3-CBC isn't, nor is its key derivation
           function.  As is, the definitive authority on this encoding scheme isn't the IETF but rather OpenSSL's
           own implementation.  ie. the implementation *is* the standard and any bugs that may exist in that
           implementation are part of the standard, as well.

           * OpenSSL is the de facto standard.  It's utilized by OpenSSH and other projects */
        if (preg_match('#DEK-Info: (.+),(.+)#', $key, $matches)) {
            $iv = Hex::decode(trim($matches[2]));
            // remove the Proc-Type / DEK-Info sections as they're no longer needed
            $key = preg_replace('#^(?:Proc-Type|DEK-Info): .*#m', '', $key);
            $ciphertext = self::_extractBER($key);
            if ($ciphertext === false) {
                $ciphertext = $key;
            }
            $crypto = self::getEncryptionObject($matches[1]);
            $crypto->setKey(self::generateSymmetricKey($password, $iv, $crypto->getKeyLength() >> 3));
            $crypto->setIV($iv);
            $key = $crypto->decrypt($ciphertext);
            if ($key === false) {
                return false;
            }
        } else {
            if (self::$format != self::MODE_DER) {
                $decoded = self::_extractBER($key);
                if ($decoded !== false) {
                    $key = $decoded;
                } elseif (self::$format == self::MODE_PEM) {
                    return false;
                }
            }
        }

        if (ord(Strings::shift($key)) != self::ASN1_SEQUENCE) {
            return false;
        }
        if (ASN1::decodeLength($key) != strlen($key)) {
            return false;
        }

        $tag = ord(Strings::shift($key));
        /* intended for keys for which OpenSSL's asn1parse returns the following:

            0:d=0  hl=4 l= 631 cons: SEQUENCE
            4:d=1  hl=2 l=   1 prim:  INTEGER           :00
            7:d=1  hl=2 l=  13 cons:  SEQUENCE
            9:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
           20:d=2  hl=2 l=   0 prim:   NULL
           22:d=1  hl=4 l= 609 prim:  OCTET STRING

           ie. PKCS8 keys */

        if ($tag == self::ASN1_INTEGER && substr($key, 0, 3) == "\x01\x00\x30") {
            Strings::shift($key, 3);
            $tag = self::ASN1_SEQUENCE;
        }

        if ($tag == self::ASN1_SEQUENCE) {
            $temp = Strings::shift($key, ASN1::decodeLength($key));
            if (ord(Strings::shift($temp)) != self::ASN1_OBJECT) {
                return false;
            }
            $length = ASN1::decodeLength($temp);
            switch (Strings::shift($temp, $length)) {
                case "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01": // rsaEncryption
                    break;
                case "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x03": // pbeWithMD5AndDES-CBC
                    /*
                       PBEParameter ::= SEQUENCE {
                           salt OCTET STRING (SIZE(8)),
                           iterationCount INTEGER }
                    */
                    if (ord(Strings::shift($temp)) != self::ASN1_SEQUENCE) {
                        return false;
                    }
                    if (ASN1::decodeLength($temp) != strlen($temp)) {
                        return false;
                    }
                    Strings::shift($temp); // assume it's an octet string
                    $salt = Strings::shift($temp, ASN1::decodeLength($temp));
                    if (ord(Strings::shift($temp)) != self::ASN1_INTEGER) {
                        return false;
                    }
                    ASN1::decodeLength($temp);
                    list(, $iterationCount) = unpack('N', str_pad($temp, 4, chr(0), STR_PAD_LEFT));
                    Strings::shift($key); // assume it's an octet string
                    $length = ASN1::decodeLength($key);
                    if (strlen($key) != $length) {
                        return false;
                    }

                    $crypto = new DES(DES::MODE_CBC);
                    $crypto->setPassword($password, 'pbkdf1', 'md5', $salt, $iterationCount);
                    $key = $crypto->decrypt($key);
                    if ($key === false) {
                        return false;
                    }
                    return self::load($key);
                default:
                    return false;
            }
            /* intended for keys for which OpenSSL's asn1parse returns the following:

                0:d=0  hl=4 l= 290 cons: SEQUENCE
                4:d=1  hl=2 l=  13 cons:  SEQUENCE
                6:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
               17:d=2  hl=2 l=   0 prim:   NULL
               19:d=1  hl=4 l= 271 prim:  BIT STRING */
            $tag = ord(Strings::shift($key)); // skip over the BIT STRING / OCTET STRING tag
            ASN1::decodeLength($key); // skip over the BIT STRING / OCTET STRING length
            // "The initial octet shall encode, as an unsigned binary integer wtih bit 1 as the least significant bit, the number of
            //  unused bits in the final subsequent octet. The number shall be in the range zero to seven."
            //  -- http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf (section 8.6.2.2)
            if ($tag == self::ASN1_BITSTRING) {
                Strings::shift($key);
            }
            if (ord(Strings::shift($key)) != self::ASN1_SEQUENCE) {
                return false;
            }
            if (ASN1::decodeLength($key) != strlen($key)) {
                return false;
            }
            $tag = ord(Strings::shift($key));
        }
        if ($tag != self::ASN1_INTEGER) {
            return false;
        }

        $length = ASN1::decodeLength($key);
        $temp = Strings::shift($key, $length);
        if (strlen($temp) != 1 || ord($temp) > 2) {
            $components['modulus'] = new BigInteger($temp, 256);
            Strings::shift($key); // skip over self::ASN1_INTEGER
            $length = ASN1::decodeLength($key);
            $components[$components['isPublicKey'] ? 'publicExponent' : 'privateExponent'] = new BigInteger(Strings::shift($key, $length), 256);

            return $components;
        }
        if (ord(Strings::shift($key)) != self::ASN1_INTEGER) {
            return false;
        }
        $length = ASN1::decodeLength($key);
        $components['modulus'] = new BigInteger(Strings::shift($key, $length), 256);
        Strings::shift($key);
        $length = ASN1::decodeLength($key);
        $components['publicExponent'] = new BigInteger(Strings::shift($key, $length), 256);
        Strings::shift($key);
        $length = ASN1::decodeLength($key);
        $components['privateExponent'] = new BigInteger(Strings::shift($key, $length), 256);
        Strings::shift($key);
        $length = ASN1::decodeLength($key);
        $components['primes'] = array(1 => new BigInteger(Strings::shift($key, $length), 256));
        Strings::shift($key);
        $length = ASN1::decodeLength($key);
        $components['primes'][] = new BigInteger(Strings::shift($key, $length), 256);
        Strings::shift($key);
        $length = ASN1::decodeLength($key);
        $components['exponents'] = array(1 => new BigInteger(Strings::shift($key, $length), 256));
        Strings::shift($key);
        $length = ASN1::decodeLength($key);
        $components['exponents'][] = new BigInteger(Strings::shift($key, $length), 256);
        Strings::shift($key);
        $length = ASN1::decodeLength($key);
        $components['coefficients'] = array(2 => new BigInteger(Strings::shift($key, $length), 256));

        if (!empty($key)) {
            if (ord(Strings::shift($key)) != self::ASN1_SEQUENCE) {
                return false;
            }
            ASN1::decodeLength($key);
            while (!empty($key)) {
                if (ord(Strings::shift($key)) != self::ASN1_SEQUENCE) {
                    return false;
                }
                ASN1::decodeLength($key);
                $key = substr($key, 1);
                $length = ASN1::decodeLength($key);
                $components['primes'][] = new BigInteger(Strings::shift($key, $length), 256);
                Strings::shift($key);
                $length = ASN1::decodeLength($key);
                $components['exponents'][] = new BigInteger(Strings::shift($key, $length), 256);
                Strings::shift($key);
                $length = ASN1::decodeLength($key);
                $components['coefficients'][] = new BigInteger(Strings::shift($key, $length), 256);
            }
        }

        return $components;
    }

    /**
     * Require base64-encoded PEM's be supplied
     *
     * @see self::load()
     * @access public
     */
    static function requirePEM()
    {
        self::$format = self::MODE_PEM;
    }

    /**
     * Require raw DER's be supplied
     *
     * @see self::load()
     * @access public
     */
    static function requireDER()
    {
        self::$format = self::MODE_DER;
    }

    /**
     * Accept any format and auto detect the format
     *
     * This is the default setting
     *
     * @see self::load()
     * @access public
     */
    static function requireAny()
    {
        self::$format = self::MODE_ANY;
    }

    /**
     * Extract raw BER from Base64 encoding
     *
     * @access private
     * @param string $str
     * @return string
     */
    static function _extractBER($str)
    {
        /* X.509 certs are assumed to be base64 encoded but sometimes they'll have additional things in them
         * above and beyond the ceritificate.
         * ie. some may have the following preceding the -----BEGIN CERTIFICATE----- line:
         *
         * Bag Attributes
         *     localKeyID: 01 00 00 00
         * subject=/O=organization/OU=org unit/CN=common name
         * issuer=/O=organization/CN=common name
         */
        $temp = preg_replace('#.*?^-+[^-]+-+[\r\n ]*$#ms', '', $str, 1);
        // remove the -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- stuff
        $temp = preg_replace('#-+[^-]+-+#', '', $temp);
        // remove new lines
        $temp = str_replace(array("\r", "\n", ' '), '', $temp);
        $temp = preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $temp) ? Base64::decode($temp) : false;
        return $temp != false ? $temp : $str;
    }
}
