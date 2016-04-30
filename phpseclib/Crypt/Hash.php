<?php

/**
 * Wrapper around hash() and hash_hmac() functions supporting truncated hashes
 * such as sha256-96.  Any hash algorithm returned by hash_algos() (and
 * truncated versions thereof) are supported.
 *
 * If {@link self::setKey() setKey()} is called, {@link self::hash() hash()} will
 * return the HMAC as opposed to the hash.
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $hash = new \phpseclib\Crypt\Hash('sha512');
 *
 *    $hash->setKey('abcdefg');
 *
 *    echo base64_encode($hash->hash('abcdefg'));
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   Hash
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2015 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt;

use phpseclib\Math\BigInteger;
use phpseclib\Exception\UnsupportedAlgorithmException;

/**
 * @package Hash
 * @author  Jim Wigginton <terrafrost@php.net>
 * @author  Andreas Fischer <bantu@phpbb.com>
 * @access  public
 */
class Hash
{
    /**
     * Hash Parameter
     *
     * @see self::setHash()
     * @var int
     * @access private
     */
    var $hashParam;

    /**
     * Byte-length of hash output (Internal HMAC)
     *
     * @see self::setHash()
     * @var int
     * @access private
     */
    var $length;

    /**
     * Hash Algorithm
     *
     * @see self::setHash()
     * @var string
     * @access private
     */
    var $hash;

    /**
     * Key
     *
     * @see self::setKey()
     * @var string
     * @access private
     */
    var $key = false;

    /**
     * Initial Hash
     *
     * Used only for sha512/*
     *
     * @see self::_sha512()
     * @var array
     * @access private
     */
    var $initial = false;

    /**
     * Outer XOR (Internal HMAC)
     *
     * Used only for sha512/*
     *
     * @see self::hash()
     * @var string
     * @access private
     */
    var $opad;

    /**
     * Inner XOR (Internal HMAC)
     *
     * Used only for sha512/*
     *
     * @see self::hash()
     * @var string
     * @access private
     */
    var $ipad;

    /**
     * Default Constructor.
     *
     * @param string $hash
     * @access public
     */
    function __construct($hash = 'sha256')
    {
        $this->setHash($hash);

        $this->ipad = str_repeat(chr(0x36), 128);
        $this->opad = str_repeat(chr(0x5C), 128);
    }

    /**
     * Sets the key for HMACs
     *
     * Keys can be of any length.
     *
     * @access public
     * @param string $key
     */
    function setKey($key = false)
    {
        $this->key = $key;
    }

    /**
     * Gets the hash function.
     *
     * As set by the constructor or by the setHash() method.
     *
     * @access public
     * @return string
     */
    function getHash()
    {
        return $this->hashParam;
    }

    /**
     * Sets the hash function.
     *
     * @access public
     * @param string $hash
     */
    function setHash($hash)
    {
        $this->hashParam = $hash = strtolower($hash);
        switch ($hash) {
            case 'md2-96':
            case 'md5-96':
            case 'sha1-96':
            case 'sha256-96':
            case 'sha512-96':
            case 'sha512/224-96':
            case 'sha512/256-96':
                $hash = substr($hash, 0, -3);
                $this->length = 12; // 96 / 8 = 12
                break;
            case 'md2':
            case 'md5':
                $this->length = 16;
                break;
            case 'sha1':
                $this->length = 20;
                break;
            case 'sha224':
            case 'sha512/224':
                $this->length = 28;
                break;
            case 'sha256':
            case 'sha512/256':
                $this->length = 32;
                break;
            case 'sha384':
                $this->length = 48;
                break;
            case 'sha512':
                $this->length = 64;
                break;
            default:
                // see if the hash isn't "officially" supported see if it can
                // be "unofficially" supported and calculate the length
                // accordingly.
                if (in_array($hash, hash_algos())) {
                    $this->length = strlen(hash($hash, '', true));
                    break;
                }
                // if the hash algorithm doens't exist maybe it's a truncated
                // hash, e.g. whirlpool-12 or some such.
                if (preg_match('#(-\d+)$#', $hash, $matches)) {
                    $hash = substr($hash, 0, -strlen($matches[1]));
                    if (in_array($hash, hash_algos())) {
                        $this->length = abs($matches[1]) >> 3;
                        break;
                    }
                }
                throw new UnsupportedAlgorithmException(
                    "$hash is not a supported algorithm"
                );
        }

        if ($hash == 'sha512/224' || $hash == 'sha512/256') {
            // from http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf#page=24
            $this->initial = $hash == 'sha512/256' ?
                array(
                    '22312194FC2BF72C', '9F555FA3C84C64C2', '2393B86B6F53B151', '963877195940EABD',
                    '96283EE2A88EFFE3', 'BE5E1E2553863992', '2B0199FC2C85B8AA', '0EB72DDC81C52CA2'
                ) :
                array(
                    '8C3D37C819544DA2', '73E1996689DCD4D6', '1DFAB7AE32FF9C82', '679DD514582F9FCF',
                    '0F6D2B697BD44DA8', '77E36F7304C48942', '3F9D85A86A1D36C8', '1112E6AD91D692A1'
                );
            for ($i = 0; $i < 8; $i++) {
                $this->initial[$i] = new BigInteger($this->initial[$i], 16);
                $this->initial[$i]->setPrecision(64);
            }
        }

        $this->hash = $hash;
    }

    /**
     * Compute the HMAC.
     *
     * @access public
     * @param string $text
     * @return string
     */
    function hash($text)
    {
        switch ($this->hash) {
            case 'sha512/224':
            case 'sha512/256':
                if (empty($this->key) || !is_string($this->key)) {
                    return substr(self::_sha512($text, $this->initial), 0, $this->length);
                }
                /* "Applications that use keys longer than B bytes will first hash the key using H and then use the
                    resultant L byte string as the actual key to HMAC."

                    -- http://tools.ietf.org/html/rfc2104#section-2 */
                $key = strlen($this->key) > $this->b ? self::_sha512($this->key, $this->initial) : $this->key;

                $key    = str_pad($this->key, 128, chr(0));       // step 1
                $temp   = $this->ipad ^ $this->key;               // step 2
                $temp  .= $text;                                  // step 3
                $temp   = self::_sha512($temp, $this->initial);   // step 4
                $output = $this->opad ^ $this->key;               // step 5
                $output.= $temp;                                  // step 6
                $output = self::_sha512($output, $this->initial); // step 7

                return substr($output, 0, $this->length);
        }
        $output = !empty($this->key) || is_string($this->key) ?
            hash_hmac($this->hash, $text, $this->key, true) :
            hash($this->hash, $text, true);

        return strlen($output) > $this->length
            ? substr($output, 0, $this->length)
            : $output;
    }

    /**
     * Returns the hash length (in bytes)
     *
     * @access public
     * @return int
     */
    function getLength()
    {
        return $this->length;
    }

    /**
     * Pure-PHP implementation of SHA512
     *
     * @access private
     * @param string $m
     */
    static function _sha512($m, $hash)
    {
        static $k;

        if (!isset($k)) {
            // Initialize table of round constants
            // (first 64 bits of the fractional parts of the cube roots of the first 80 primes 2..409)
            $k = array(
                '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc',
                '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
                'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2',
                '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
                'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
                '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
                '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4',
                'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
                '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df',
                '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
                'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30',
                'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
                '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8',
                '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
                '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
                '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
                'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178',
                '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
                '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c',
                '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817'
            );

            for ($i = 0; $i < 80; $i++) {
                $k[$i] = new BigInteger($k[$i], 16);
            }
        }

        // Pre-processing
        $length = strlen($m);
        // to round to nearest 112 mod 128, we'll add 128 - (length + (128 - 112)) % 128
        $m.= str_repeat(chr(0), 128 - (($length + 16) & 0x7F));
        $m[$length] = chr(0x80);
        // we don't support hashing strings 512MB long
        $m.= pack('N4', 0, 0, 0, $length << 3);

        // Process the message in successive 1024-bit chunks
        $chunks = str_split($m, 128);
        foreach ($chunks as $chunk) {
            $w = array();
            for ($i = 0; $i < 16; $i++) {
                $temp = new BigInteger(self::_string_shift($chunk, 8), 256);
                $temp->setPrecision(64);
                $w[] = $temp;
            }

            // Extend the sixteen 32-bit words into eighty 32-bit words
            for ($i = 16; $i < 80; $i++) {
                $temp = array(
                          $w[$i - 15]->bitwise_rightRotate(1),
                          $w[$i - 15]->bitwise_rightRotate(8),
                          $w[$i - 15]->bitwise_rightShift(7)
                );
                $s0 = $temp[0]->bitwise_xor($temp[1]);
                $s0 = $s0->bitwise_xor($temp[2]);
                $temp = array(
                          $w[$i - 2]->bitwise_rightRotate(19),
                          $w[$i - 2]->bitwise_rightRotate(61),
                          $w[$i - 2]->bitwise_rightShift(6)
                );
                $s1 = $temp[0]->bitwise_xor($temp[1]);
                $s1 = $s1->bitwise_xor($temp[2]);
                $w[$i] = clone $w[$i - 16];
                $w[$i] = $w[$i]->add($s0);
                $w[$i] = $w[$i]->add($w[$i - 7]);
                $w[$i] = $w[$i]->add($s1);
            }

            // Initialize hash value for this chunk
            $a = clone $hash[0];
            $b = clone $hash[1];
            $c = clone $hash[2];
            $d = clone $hash[3];
            $e = clone $hash[4];
            $f = clone $hash[5];
            $g = clone $hash[6];
            $h = clone $hash[7];

            // Main loop
            for ($i = 0; $i < 80; $i++) {
                $temp = array(
                    $a->bitwise_rightRotate(28),
                    $a->bitwise_rightRotate(34),
                    $a->bitwise_rightRotate(39)
                );
                $s0 = $temp[0]->bitwise_xor($temp[1]);
                $s0 = $s0->bitwise_xor($temp[2]);
                $temp = array(
                    $a->bitwise_and($b),
                    $a->bitwise_and($c),
                    $b->bitwise_and($c)
                );
                $maj = $temp[0]->bitwise_xor($temp[1]);
                $maj = $maj->bitwise_xor($temp[2]);
                $t2 = $s0->add($maj);

                $temp = array(
                    $e->bitwise_rightRotate(14),
                    $e->bitwise_rightRotate(18),
                    $e->bitwise_rightRotate(41)
                );
                $s1 = $temp[0]->bitwise_xor($temp[1]);
                $s1 = $s1->bitwise_xor($temp[2]);
                $temp = array(
                    $e->bitwise_and($f),
                    $g->bitwise_and($e->bitwise_not())
                );
                $ch = $temp[0]->bitwise_xor($temp[1]);
                $t1 = $h->add($s1);
                $t1 = $t1->add($ch);
                $t1 = $t1->add($k[$i]);
                $t1 = $t1->add($w[$i]);

                $h = clone $g;
                $g = clone $f;
                $f = clone $e;
                $e = $d->add($t1);
                $d = clone $c;
                $c = clone $b;
                $b = clone $a;
                $a = $t1->add($t2);
            }

            // Add this chunk's hash to result so far
            $hash = array(
                $hash[0]->add($a),
                $hash[1]->add($b),
                $hash[2]->add($c),
                $hash[3]->add($d),
                $hash[4]->add($e),
                $hash[5]->add($f),
                $hash[6]->add($g),
                $hash[7]->add($h)
            );
        }

        // Produce the final hash value (big-endian)
        // (\phpseclib\Crypt\Hash::hash() trims the output for hashes but not for HMACs.  as such, we trim the output here)
        $temp = $hash[0]->toBytes() . $hash[1]->toBytes() . $hash[2]->toBytes() . $hash[3]->toBytes() .
                $hash[4]->toBytes() . $hash[5]->toBytes() . $hash[6]->toBytes() . $hash[7]->toBytes();

        return $temp;
    }

    /**
     * String Shift
     *
     * Inspired by array_shift
     *
     * @param string $string
     * @param int $index
     * @return string
     * @access private
     */
    static function _string_shift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }
}
