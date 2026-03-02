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
 *    $hash = new \phpseclib4\Crypt\Hash('sha512');
 *
 *    $hash->setKey('abcdefg');
 *
 *    echo base64_encode($hash->hash('abcdefg'));
 * ?>
 * </code>
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2015 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Exception\InsufficientSetupException;
use phpseclib4\Exception\LengthException;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\Math\BigInteger;
use phpseclib4\Math\PrimeField;

/**
 * @author  Jim Wigginton <terrafrost@php.net>
 * @author  Andreas Fischer <bantu@phpbb.com>
 */
class Hash
{
    use Common\Traits\PKCS12Helper;

    /**
     * Padding Types
     */
    public const PADDING_KECCAK = 1;

    /**
     * Padding Types
     */
    public const PADDING_SHA3 = 2;

    /**
     * Padding Types
     */
    public const PADDING_SHAKE = 3;

    /**
     * Padding Type
     *
     * Only used by SHA3
     *
     * @var int
     */
    private $paddingType = 0;

    /**
     * Hash Parameter
     *
     * @see self::setHash()
     * @var int
     */
    private $hashParam;

    /**
     * Byte-length of hash output (Internal HMAC)
     *
     * @see self::setHash()
     * @var int
     */
    private $length;

    /**
     * Hash Algorithm
     *
     * @see self::setHash()
     * @var string
     */
    private $algo;

    /**
     * Key
     *
     * @see self::setKey()
     * @var string
     */
    private $key = false;

    /**
     * Nonce
     *
     * @see self::setNonce()
     * @var string
     */
    private $nonce = false;

    /**
     * Hash Parameters
     *
     * @var array
     */
    private $parameters = [];

    /**
     * Computed Key
     *
     * @see self::_computeKey()
     * @var string
     */
    private $computedKey = false;

    /**
     * Outer XOR (Internal HMAC)
     *
     * Used only for sha512
     *
     * @see self::hash()
     * @var string
     */
    private $opad;

    /**
     * Inner XOR (Internal HMAC)
     *
     * Used only for sha512
     *
     * @see self::hash()
     * @var string
     */
    private $ipad;

    /**
     * Recompute AES Key
     *
     * Used only for umac
     *
     * @see self::hash()
     * @var boolean
     */
    private $recomputeAESKey;

    /**
     * umac cipher object
     *
     * @see self::hash()
     * @var AES
     */
    private $c;

    /**
     * umac pad
     *
     * @see self::hash()
     * @var string
     */
    private $pad;

    /**
     * Block Size
     *
     * @var int
     */
    private $blockSize;

    /**#@+
     * UMAC variables
     *
     * @var PrimeField
     */
    private static $factory36;
    private static $factory64;
    private static $factory128;
    private static $offset64;
    private static $offset128;
    private static $marker64;
    private static $marker128;
    private static $maxwordrange64;
    private static $maxwordrange128;
    /**#@-*/

    /**#@+
     * AES_CMAC variables
     *
     * @var string
     */
    private $k1;
    private $k2;
    /**#@-*/

    /**
     * Default Constructor.
     */
    public function __construct(string $hash = 'sha256')
    {
        $this->setHash($hash);
    }

    /**
     * Sets the key for HMACs
     *
     * Keys can be of any length.
     *
     * @param string $key
     */
    public function setKey($key = false): void
    {
        $this->key = $key;
        $this->computeKey();
        $this->recomputeAESKey = true;
    }

    /**
     * Sets the nonce for UMACs
     *
     * Keys can be of any length.
     *
     * @param string $nonce
     */
    public function setNonce($nonce = false): void
    {
        switch (true) {
            case !is_string($nonce):
            case strlen($nonce) > 0 && strlen($nonce) <= 16:
                $this->recomputeAESKey = true;
                $this->nonce = $nonce;
                return;
        }

        throw new LengthException('The nonce length must be between 1 and 16 bytes, inclusive');
    }

    /**
     * Pre-compute the key used by the HMAC
     *
     * Quoting http://tools.ietf.org/html/rfc2104#section-2, "Applications that use keys longer than B bytes
     * will first hash the key using H and then use the resultant L byte string as the actual key to HMAC."
     *
     * As documented in https://www.reddit.com/r/PHP/comments/9nct2l/symfonypolyfill_hash_pbkdf2_correct_fix_for/
     * when doing an HMAC multiple times it's faster to compute the hash once instead of computing it during
     * every call
     */
    private function computeKey(): void
    {
        if ($this->key === false) {
            $this->computedKey = false;
            return;
        }

        if (strlen($this->key) <= $this->getBlockLengthInBytes()) {
            $this->computedKey = $this->key;
            return;
        }

        $this->computedKey = is_array($this->algo) ?
            call_user_func($this->algo, $this->key) :
            hash($this->algo, $this->key, true);
    }

    /**
     * Gets the hash function.
     *
     * As set by the constructor or by the setHash() method.
     *
     * @return string
     */
    public function getHash()
    {
        return $this->hashParam;
    }

    /**
     * Sets the hash function.
     */
    public function setHash(string $hash): void
    {
        $oldHash = $this->hashParam;
        $this->hashParam = $hash = strtolower($hash);
        switch ($hash) {
            case 'umac-32':
            case 'umac-64':
            case 'umac-96':
            case 'umac-128':
                if ($oldHash != $this->hashParam) {
                    $this->recomputeAESKey = true;
                }
                $this->blockSize = 128;
                $this->length = abs((int) substr($hash, -3)) >> 3;
                $this->algo = 'umac';
                return;
            case 'aes_cmac':
                if ($oldHash != $this->hashParam) {
                    $this->recomputeAESKey = true;
                }
                $this->blockSize = 128;
                $this->length = 16;
                $this->algo = 'aes_cmac';
                return;
            case 'md2-96':
            case 'md5-96':
            case 'sha1-96':
            case 'sha224-96':
            case 'sha256-96':
            case 'sha384-96':
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
            case 'sha3-224':
                $this->length = 28;
                break;
            case 'keccak256':
                $this->paddingType = self::PADDING_KECCAK;
                // fall-through
            case 'sha256':
            case 'sha512/256':
            case 'sha3-256':
                $this->length = 32;
                break;
            case 'sha384':
            case 'sha3-384':
                $this->length = 48;
                break;
            case 'sha512':
            case 'sha3-512':
                $this->length = 64;
                break;
            default:
                if (preg_match('#^(shake(?:128|256))-(\d+)$#', $hash, $matches)) {
                    $this->paddingType = self::PADDING_SHAKE;
                    $hash = $matches[1];
                    $this->length = $matches[2] >> 3;
                } else {
                    throw new UnsupportedAlgorithmException(
                        "$hash is not a supported algorithm"
                    );
                }
        }

        switch ($hash) {
            case 'md2':
            case 'md2-96':
                $this->blockSize = 128;
                break;
            case 'md5-96':
            case 'sha1-96':
            case 'sha224-96':
            case 'sha256-96':
            case 'md5':
            case 'sha1':
            case 'sha224':
            case 'sha256':
                $this->blockSize = 512;
                break;
            case 'sha3-224':
                $this->blockSize = 1152; // 1600 - 2*224
                break;
            case 'sha3-256':
            case 'shake256':
            case 'keccak256':
                $this->blockSize = 1088; // 1600 - 2*256
                break;
            case 'sha3-384':
                $this->blockSize = 832; // 1600 - 2*384
                break;
            case 'sha3-512':
                $this->blockSize = 576; // 1600 - 2*512
                break;
            case 'shake128':
                $this->blockSize = 1344; // 1600 - 2*128
                break;
            default:
                $this->blockSize = 1024;
        }

        if (in_array(substr($hash, 0, 5), ['shake', 'kecca'])) {
            //preg_match('#(\d+)$#', $hash, $matches);
            //$this->parameters['capacity'] = 2 * $matches[1]; // 1600 - $this->blockSize
            //$this->parameters['rate'] = 1600 - $this->parameters['capacity']; // == $this->blockSize
            if (!$this->paddingType) {
                $this->paddingType = self::PADDING_SHA3;
            }
            $this->parameters = [
                'capacity' => 1600 - $this->blockSize,
                'rate' => $this->blockSize,
                'length' => $this->length,
                'padding' => $this->paddingType,
            ];
            $hash = ['phpseclib4\Crypt\Hash', PHP_INT_SIZE == 8 ? 'sha3_64' : 'sha3_32'];
        }

        if (is_array($hash)) {
            $b = $this->blockSize >> 3;
            $this->ipad = str_repeat(chr(0x36), $b);
            $this->opad = str_repeat(chr(0x5C), $b);
        }

        $this->algo = $hash;

        $this->computeKey();
    }

    /**
     * KDF: Key-Derivation Function
     *
     * The key-derivation function generates pseudorandom bits used to key the hash functions.
     *
     * @param int $index a non-negative integer less than 2^64
     * @param int $numbytes a non-negative integer less than 2^64
     * @return string string of length numbytes bytes
     */
    private function kdf(int $index, int $numbytes): string
    {
        $this->c->setIV(pack('N4', 0, $index, 0, 1));

        return $this->c->encrypt(str_repeat("\0", $numbytes));
    }

    /**
     * PDF Algorithm
     *
     * @return string string of length taglen bytes.
     */
    private function pdf(): string
    {
        $k = $this->key;
        $nonce = $this->nonce;
        $taglen = $this->length;

        //
        // Extract and zero low bit(s) of Nonce if needed
        //
        if ($taglen <= 8) {
            $last = strlen($nonce) - 1;
            $mask = $taglen == 4 ? "\3" : "\1";
            $index = $nonce[$last] & $mask;
            $nonce[$last] = $nonce[$last] ^ $index;
        }

        //
        // Make Nonce BLOCKLEN bytes by appending zeroes if needed
        //
        $nonce = str_pad($nonce, 16, "\0");

        //
        // Generate subkey, encipher and extract indexed substring
        //
        $kp = $this->kdf(0, 16);
        $c = new AES('ctr');
        $c->disablePadding();
        $c->setKey($kp);
        $c->setIV($nonce);
        $t = $c->encrypt("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");

        // we could use ord() but per https://paragonie.com/blog/2016/06/constant-time-encoding-boring-cryptography-rfc-4648-and-you
        // unpack() doesn't leak timing info
        return $taglen <= 8 ?
            substr($t, unpack('C', $index)[1] * $taglen, $taglen) :
            substr($t, 0, $taglen);
    }

    /**
     * UHASH Algorithm
     *
     * @param string $m string of length less than 2^67 bits.
     * @param int $taglen the integer 4, 8, 12 or 16.
     * @return string string of length taglen bytes.
     */
    private function uhash(string $m, int $taglen): string
    {
        //
        // One internal iteration per 4 bytes of output
        //
        $iters = $taglen >> 2;

        //
        // Define total key needed for all iterations using KDF.
        // L1Key reuses most key material between iterations.
        //
        //$L1Key  = $this->kdf(1, 1024 + ($iters - 1) * 16);
        $L1Key  = $this->kdf(1, (1024 + ($iters - 1)) * 16);
        $L2Key  = $this->kdf(2, $iters * 24);
        $L3Key1 = $this->kdf(3, $iters * 64);
        $L3Key2 = $this->kdf(4, $iters * 4);

        //
        // For each iteration, extract key and do three-layer hash.
        // If bytelength(M) <= 1024, then skip L2-HASH.
        //
        $y = '';
        for ($i = 0; $i < $iters; $i++) {
            $L1Key_i  = substr($L1Key, $i * 16, 1024);
            $L2Key_i  = substr($L2Key, $i * 24, 24);
            $L3Key1_i = substr($L3Key1, $i * 64, 64);
            $L3Key2_i = substr($L3Key2, $i * 4, 4);

            $a = self::L1Hash($L1Key_i, $m);
            $b = strlen($m) <= 1024 ? "\0\0\0\0\0\0\0\0$a" : self::L2Hash($L2Key_i, $a);
            $c = self::L3Hash($L3Key1_i, $L3Key2_i, $b);
            $y .= $c;
        }

        return $y;
    }

    /**
     * L1-HASH Algorithm
     *
     * The first-layer hash breaks the message into 1024-byte chunks and
     * hashes each with a function called NH.  Concatenating the results
     * forms a string, which is up to 128 times shorter than the original.
     *
     * @param string $k string of length 1024 bytes.
     * @param string $m string of length less than 2^67 bits.
     * @return string string of length (8 * ceil(bitlength(M)/8192)) bytes.
     */
    private static function L1Hash(string $k, string $m): string
    {
        //
        // Break M into 1024 byte chunks (final chunk may be shorter)
        //
        $m = str_split($m, 1024);

        //
        // For each chunk, except the last: endian-adjust, NH hash
        // and add bit-length.  Use results to build Y.
        //
        $length = 1024 * 8;
        $y = '';

        for ($i = 0; $i < count($m) - 1; $i++) {
            $m[$i] = pack('N*', ...unpack('V*', $m[$i])); // ENDIAN-SWAP
            $y .= PHP_INT_SIZE == 8 ?
                static::nh64($k, $m[$i], $length) :
                static::nh32($k, $m[$i], $length);
        }

        //
        // For the last chunk: pad to 32-byte boundary, endian-adjust,
        // NH hash and add bit-length.  Concatenate the result to Y.
        //
        $length = count($m) ? strlen($m[$i]) : 0;
        $pad = 32 - ($length % 32);
        $pad = max(32, $length + $pad % 32);
        $m[$i] = str_pad($m[$i] ?? '', $pad, "\0"); // zeropad
        $m[$i] = pack('N*', ...unpack('V*', $m[$i])); // ENDIAN-SWAP

        $y .= PHP_INT_SIZE == 8 ?
            static::nh64($k, $m[$i], $length * 8) :
            static::nh32($k, $m[$i], $length * 8);

        return $y;
    }

    /**
     * 32-bit safe 64-bit Multiply with 2x 32-bit ints
     *
     * @param int $x
     * @param int $y
     * @return string $x * $y
     */
    private static function mul32_64($x, $y)
    {
        // see mul64() for a more detailed explanation of how this works

        $x1 = ($x >> 16) & 0xFFFF;
        $x0 = $x & 0xFFFF;

        $y1 = ($y >> 16) & 0xFFFF;
        $y0 = $y & 0xFFFF;

        // the following 3x lines will possibly yield floats
        $z2 = $x1 * $y1;
        $z0 = $x0 * $y0;
        $z1 = $x1 * $y0 + $x0 * $y1;

        $a = intval(fmod($z0, 65536));
        $b = intval($z0 / 65536) + intval(fmod($z1, 65536));
        $c = intval($z1 / 65536) + intval(fmod($z2, 65536)) + intval($b / 65536);
        $b = intval(fmod($b, 65536));
        $d = intval($z2 / 65536) + intval($c / 65536);
        $c = intval(fmod($c, 65536));
        $d = intval(fmod($d, 65536));

        return pack('n4', $d, $c, $b, $a);
    }

    /**
     * 32-bit safe 64-bit Addition with 2x 64-bit strings
     *
     * @param int $x
     * @param int $y
     * @return int $x * $y
     */
    private static function add32_64($x, $y)
    {
        [, $x1, $x2, $x3, $x4] = unpack('n4', $x);
        [, $y1, $y2, $y3, $y4] = unpack('n4', $y);
        $a = $x4 + $y4;
        $b = $x3 + $y3 + ($a >> 16);
        $c = $x2 + $y2 + ($b >> 16);
        $d = $x1 + $y1 + ($c >> 16);
        return pack('n4', $d, $c, $b, $a);
    }

    /**
     * 32-bit safe 32-bit Addition with 2x 32-bit strings
     *
     * @param int $x
     * @param int $y
     * @return int $x * $y
     */
    private static function add32($x, $y)
    {
        // see add64() for a more detailed explanation of how this works

        $x1 = $x & 0xFFFF;
        $x2 = ($x >> 16) & 0xFFFF;
        $y1 = $y & 0xFFFF;
        $y2 = ($y >> 16) & 0xFFFF;

        $a = $x1 + $y1;
        $b = ($x2 + $y2 + ($a >> 16)) << 16;
        $a &= 0xFFFF;

        return $a | $b;
    }

    /**
     * NH Algorithm / 32-bit safe
     *
     * @param string $k string of length 1024 bytes.
     * @param string $m string with length divisible by 32 bytes.
     * @return string string of length 8 bytes.
     */
    private static function nh32(string $k, string $m, int $length): string
    {
        //
        // Break M and K into 4-byte chunks
        //
        $k = unpack('N*', $k);
        $m = unpack('N*', $m);
        $t = count($m);

        //
        // Perform NH hash on the chunks, pairing words for multiplication
        // which are 4 apart to accommodate vector-parallelism.
        //
        $i = 1;
        $y = "\0\0\0\0\0\0\0\0";
        while ($i <= $t) {
            $temp  = self::add32($m[$i], $k[$i]);
            $temp2 = self::add32($m[$i + 4], $k[$i + 4]);
            $y = self::add32_64($y, self::mul32_64($temp, $temp2));

            $temp  = self::add32($m[$i + 1], $k[$i + 1]);
            $temp2 = self::add32($m[$i + 5], $k[$i + 5]);
            $y = self::add32_64($y, self::mul32_64($temp, $temp2));

            $temp  = self::add32($m[$i + 2], $k[$i + 2]);
            $temp2 = self::add32($m[$i + 6], $k[$i + 6]);
            $y = self::add32_64($y, self::mul32_64($temp, $temp2));

            $temp  = self::add32($m[$i + 3], $k[$i + 3]);
            $temp2 = self::add32($m[$i + 7], $k[$i + 7]);
            $y = self::add32_64($y, self::mul32_64($temp, $temp2));

            $i += 8;
        }

        return self::add32_64($y, pack('N2', 0, $length));
    }

    /**
     * 64-bit Multiply with 2x 32-bit ints
     */
    private static function mul64(int $x, int $y): int
    {
        // since PHP doesn't implement unsigned integers we'll implement them with signed integers
        // to do this we'll use karatsuba multiplication

        $x1 = $x >> 16;
        $x0 = $x & 0xFFFF;

        $y1 = $y >> 16;
        $y0 = $y & 0xFFFF;

        $z2 = $x1 * $y1; // up to 32 bits long
        $z0 = $x0 * $y0; // up to 32 bits long
        $z1 = $x1 * $y0 + $x0 * $y1; // up to 33 bit long
        // normally karatsuba multiplication calculates $z1 thusly:
        //$z1 = ($x1 + $x0) * ($y0 + $y1) - $z2 - $z0;
        // the idea being to eliminate one extra multiplication. for arbitrary precision math that makes sense
        // but not for this purpose

        // at this point karatsuba would normally return this:
        //return ($z2 << 64) + ($z1 << 32) + $z0;
        // the problem is that the output could be out of range for signed 64-bit ints,
        // which would cause PHP to switch to floats, which would risk losing the lower few bits
        // as such we'll OR 4x 16-bit blocks together like so:
        /*
          ........  |  ........  |  ........  |  ........
          upper $z2 |  lower $z2 |  lower $z1 |  lower $z0
                    | +upper $z1 | +upper $z0 |
         +   $carry | +   $carry |            |
        */
        // technically upper $z1 is 17 bit - not 16 - but the most significant digit of that will
        // just get added to $carry

        $a = $z0 & 0xFFFF;
        $b = ($z0 >> 16) + ($z1 & 0xFFFF);
        $c = ($z1 >> 16) + ($z2 & 0xFFFF) + ($b >> 16);
        $b = ($b & 0xFFFF) << 16;
        $d = ($z2 >> 16) + ($c >> 16);
        $c = ($c & 0xFFFF) << 32;
        $d = ($d & 0xFFFF) << 48;

        return $a | $b | $c | $d;
    }

    /**
     * 64-bit Addition with 2x 64-bit ints
     */
    private static function add64(int $x, int $y): int
    {
        // doing $x + $y risks returning a result that's out of range for signed 64-bit ints
        // in that event PHP would convert the result to a float and precision would be lost
        // so we'll just add 2x 32-bit ints together like so:
        /*
           ........ | ........
           upper $x | lower $x
          +upper $y |+lower $y
          +  $carry |
        */
        $x1 = $x & 0xFFFFFFFF;
        $x2 = ($x >> 32) & 0xFFFFFFFF;
        $y1 = $y & 0xFFFFFFFF;
        $y2 = ($y >> 32) & 0xFFFFFFFF;

        $a = $x1 + $y1;
        $b = ($x2 + $y2 + ($a >> 32)) << 32;
        $a &= 0xFFFFFFFF;

        return $a | $b;
    }

    /**
     * NH Algorithm / 64-bit safe
     *
     * @param string $k string of length 1024 bytes.
     * @param string $m string with length divisible by 32 bytes.
     * @return string string of length 8 bytes.
     */
    private static function nh64($k, $m, $length)
    {
        //
        // Break M and K into 4-byte chunks
        //
        $k = unpack('N*', $k);
        $m = unpack('N*', $m);
        $t = count($m);

        //
        // Perform NH hash on the chunks, pairing words for multiplication
        // which are 4 apart to accommodate vector-parallelism.
        //
        $i = 1;
        $y = 0;
        while ($i <= $t) {
            $temp  = ($m[$i] + $k[$i]) & 0xFFFFFFFF;
            $temp2 = ($m[$i + 4] + $k[$i + 4]) & 0xFFFFFFFF;
            $y = self::add64($y, self::mul64($temp, $temp2));

            $temp  = ($m[$i + 1] + $k[$i + 1]) & 0xFFFFFFFF;
            $temp2 = ($m[$i + 5] + $k[$i + 5]) & 0xFFFFFFFF;
            $y = self::add64($y, self::mul64($temp, $temp2));

            $temp  = ($m[$i + 2] + $k[$i + 2]) & 0xFFFFFFFF;
            $temp2 = ($m[$i + 6] + $k[$i + 6]) & 0xFFFFFFFF;
            $y = self::add64($y, self::mul64($temp, $temp2));

            $temp  = ($m[$i + 3] + $k[$i + 3]) & 0xFFFFFFFF;
            $temp2 = ($m[$i + 7] + $k[$i + 7]) & 0xFFFFFFFF;
            $y = self::add64($y, self::mul64($temp, $temp2));

            $i += 8;
        }

        return pack('J', self::add64($y, $length));
    }

    /**
     * L2-HASH: Second-Layer Hash
     *
     * The second-layer rehashes the L1-HASH output using a polynomial hash
     * called POLY.  If the L1-HASH output is long, then POLY is called once
     * on a prefix of the L1-HASH output and called using different settings
     * on the remainder.  (This two-step hashing of the L1-HASH output is
     * needed only if the message length is greater than 16 megabytes.)
     * Careful implementation of POLY is necessary to avoid a possible
     * timing attack (see Section 6.6 for more information).
     *
     * @param string $k string of length 24 bytes.
     * @param string $m string of length less than 2^64 bytes.
     * @return string string of length 16 bytes.
     */
    private static function L2Hash(string $k, string $m): string
    {
        //
        //  Extract keys and restrict to special key-sets
        //
        $k64 = $k & "\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF";
        $k64 = new BigInteger($k64, 256);
        $k128 = substr($k, 8) & "\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF";
        $k128 = new BigInteger($k128, 256);

        //
        // If M is no more than 2^17 bytes, hash under 64-bit prime,
        // otherwise, hash first 2^17 bytes under 64-bit prime and
        // remainder under 128-bit prime.
        //
        if (strlen($m) <= 0x20000) { // 2^14 64-bit words
            $y = self::poly(64, self::$maxwordrange64, $k64, $m);
        } else {
            $m_1 = substr($m, 0, 0x20000); // 1 << 17
            $m_2 = substr($m, 0x20000) . "\x80";
            $length = strlen($m_2);
            $pad = 16 - ($length % 16);
            $pad %= 16;
            $m_2 = str_pad($m_2, $length + $pad, "\0"); // zeropad
            $y = self::poly(64, self::$maxwordrange64, $k64, $m_1);
            $y = str_pad($y, 16, "\0", STR_PAD_LEFT);
            $y = self::poly(128, self::$maxwordrange128, $k128, $y . $m_2);
        }

        return str_pad($y, 16, "\0", STR_PAD_LEFT);
    }

    /**
     * POLY Algorithm
     *
     * @param int $wordbits the integer 64 or 128.
     * @param PrimeField\Integer $maxwordrange positive integer less than 2^wordbits.
     * @param BigInteger $k integer in the range 0 ... prime(wordbits) - 1.
     * @param string $m string with length divisible by (wordbits / 8) bytes.
     * @return string in the range 0 ... prime(wordbits) - 1.
     */
    private static function poly(int $wordbits, PrimeField\Integer $maxwordrange, BigInteger $k, string $m): string
    {
        //
        // Define constants used for fixing out-of-range words
        //
        $wordbytes = $wordbits >> 3;
        if ($wordbits == 128) {
            $factory = self::$factory128;
            $offset = self::$offset128;
            $marker = self::$marker128;
        } else {
            $factory = self::$factory64;
            $offset = self::$offset64;
            $marker = self::$marker64;
        }

        $k = $factory->newInteger($k);

        //
        // Break M into chunks of length wordbytes bytes
        //
        $m_i = str_split($m, $wordbytes);

        //
        // Each input word m is compared with maxwordrange.  If not smaller
        // then 'marker' and (m - offset), both in range, are hashed.
        //
        $y = $factory->newInteger(new BigInteger(1));
        foreach ($m_i as $m) {
            $m = $factory->newInteger(new BigInteger($m, 256));
            if ($m->compare($maxwordrange) >= 0) {
                $y = $k->multiply($y)->add($marker);
                $y = $k->multiply($y)->add($m->subtract($offset));
            } else {
                $y = $k->multiply($y)->add($m);
            }
        }

        return $y->toBytes();
    }

    /**
     * L3-HASH: Third-Layer Hash
     *
     * The output from L2-HASH is 16 bytes long.  This final hash function
     * hashes the 16-byte string to a fixed length of 4 bytes.
     *
     * @param string $k1 string of length 64 bytes.
     * @param string $k2 string of length 4 bytes.
     * @param string $m string of length 16 bytes.
     * @return string string of length 4 bytes.
     */
    private static function L3Hash(string $k1, string $k2, string $m): string
    {
        $factory = self::$factory36;

        $y = $factory->newInteger(new BigInteger());
        for ($i = 0; $i < 8; $i++) {
            $m_i = $factory->newInteger(new BigInteger(substr($m, 2 * $i, 2), 256));
            $k_i = $factory->newInteger(new BigInteger(substr($k1, 8 * $i, 8), 256));
            $y = $y->add($m_i->multiply($k_i));
        }
        $y = str_pad(substr($y->toBytes(), -4), 4, "\0", STR_PAD_LEFT);
        $y = $y ^ $k2;

        return $y;
    }

    /**
     * Compute the Hash / HMAC / UMAC.
     *
     * @param string|resource $text
     */
    public function hash(mixed $text): string
    {
        if (!is_string($text) && !is_resource($text)) {
            throw new UnexpectedValueException('$text must be either a string or a resource');
        }
        $algo = $this->algo;
        // https://www.rfc-editor.org/rfc/rfc4493.html
        // https://en.wikipedia.org/wiki/One-key_MAC
        if ($algo == 'aes_cmac') {
            if (is_resource($text)) {
                throw new RuntimeException('aes_cmac only works with strings');
            }
            $constZero = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
            if ($this->recomputeAESKey) {
                if (!is_string($this->key)) {
                    throw new InsufficientSetupException('No key has been set');
                }
                if (strlen($this->key) != 16) {
                    throw new LengthException('Key must be 16 bytes long');
                }
                // Algorithm Generate_Subkey
                $constRb = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x87";
                $this->c = new AES('ecb');
                $this->c->setKey($this->key);
                $this->c->disablePadding();
                $l = $this->c->encrypt($constZero);
                $msb = ($l & "\x80") == "\x80";
                $l = new BigInteger($l, 256);
                $l->setPrecision(128);
                $l = $l->bitwise_leftShift(1)->toBytes();
                // make it constant time
                $k1 = $msb ? $l ^ $constRb : $l | $constZero;

                $msb = ($k1 & "\x80") == "\x80";
                $k2 = new BigInteger($k1, 256);
                $k2->setPrecision(128);
                $k2 = $k2->bitwise_leftShift(1)->toBytes();
                // make it constant time
                $k2 = $msb ? $k2 ^ $constRb : $k2 | $constZero;

                $this->k1 = $k1;
                $this->k2 = $k2;
            }

            $len = strlen($text);
            $const_Bsize = 16;
            $M = strlen($text) ? str_split($text, $const_Bsize) : [''];

            // Step 2
            $n = ceil($len / $const_Bsize);
            // Step 3
            if ($n == 0) {
                $n = 1;
                $flag = false;
            } else {
                $flag = $len % $const_Bsize == 0;
            }
            // Step 4
            $M_last = $flag ?
                $M[$n - 1] ^ $k1 :
                self::OMAC_padding($M[$n - 1], $const_Bsize) ^ $k2;
            // Step 5
            $x = $constZero;
            // Step 6
            $c = &$this->c;
            for ($i = 0; $i < $n - 1; $i++) {
                $y = $x ^ $M[$i];
                $x = $c->encrypt($y);
            }
            $y = $M_last ^ $x;
            return $c->encrypt($y);
        }
        if ($algo == 'umac') {
            if (is_resource($text)) {
                throw new RuntimeException('umac only works with strings');
            }
            if ($this->recomputeAESKey) {
                if (!is_string($this->nonce)) {
                    throw new InsufficientSetupException('No nonce has been set');
                }
                if (!is_string($this->key)) {
                    throw new InsufficientSetupException('No key has been set');
                }
                if (strlen($this->key) != 16) {
                    throw new LengthException('Key must be 16 bytes long');
                }

                if (!isset(self::$maxwordrange64)) {
                    $one = new BigInteger(1);

                    $prime36 = new BigInteger("\x00\x00\x00\x0F\xFF\xFF\xFF\xFB", 256);
                    self::$factory36 = new PrimeField($prime36);

                    $prime64 = new BigInteger("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC5", 256);
                    self::$factory64 = new PrimeField($prime64);

                    $prime128 = new BigInteger("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x61", 256);
                    self::$factory128 = new PrimeField($prime128);

                    self::$offset64 = new BigInteger("\1\0\0\0\0\0\0\0\0", 256);
                    self::$offset64 = self::$factory64->newInteger(self::$offset64->subtract($prime64));
                    self::$offset128 = new BigInteger("\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 256);
                    self::$offset128 = self::$factory128->newInteger(self::$offset128->subtract($prime128));

                    self::$marker64 = self::$factory64->newInteger($prime64->subtract($one));
                    self::$marker128 = self::$factory128->newInteger($prime128->subtract($one));

                    $maxwordrange64 = $one->bitwise_leftShift(64)->subtract($one->bitwise_leftShift(32));
                    self::$maxwordrange64 = self::$factory64->newInteger($maxwordrange64);

                    $maxwordrange128 = $one->bitwise_leftShift(128)->subtract($one->bitwise_leftShift(96));
                    self::$maxwordrange128 = self::$factory128->newInteger($maxwordrange128);
                }

                $this->c = new AES('ctr');
                $this->c->disablePadding();
                $this->c->setKey($this->key);

                $this->pad = $this->pdf();

                $this->recomputeAESKey = false;
            }

            $hashedmessage = $this->uhash($text, $this->length);
            return $hashedmessage ^ $this->pad;
        }

        if (is_array($algo)) {
            if (is_resource($algo)) {
                throw new RuntimeException($this->hashParam . ' only works with strings');
            }
            if (empty($this->key) || !is_string($this->key)) {
                return substr($algo($text, ...array_values($this->parameters)), 0, $this->length);
            }

            // SHA3 HMACs are discussed at https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=30

            $key    = str_pad($this->computedKey, $b, chr(0));
            $temp   = $this->ipad ^ $key;
            $temp  .= $text;
            $temp   = substr($algo($temp, ...array_values($this->parameters)), 0, $this->length);
            $output = $this->opad ^ $key;
            $output .= $temp;
            $output = $algo($output, ...array_values($this->parameters));

            return substr($output, 0, $this->length);
        }

        if (is_resource($text)) {
            $pos = ftell($text);
            rewind($text);
            $ctx = !empty($this->key) || is_string($this->key) ?
                hash_init($algo, HASH_HMAC, $this->computedKey) :
                hash_init($algo);
            hash_update_stream($ctx, $text);
            fseek($text, $pos);
            $output = hash_final($ctx, true);
        } else {
            $output = !empty($this->key) || is_string($this->key) ?
                hash_hmac($algo, $text, $this->computedKey, true) :
                hash($algo, $text, true);
        }

        return strlen($output) > $this->length
            ? substr($output, 0, $this->length)
            : $output;
    }

    /**
     * Returns the hash length (in bits)
     */
    public function getLength(): int
    {
        return $this->length << 3;
    }

    /**
     * Returns the hash length (in bytes)
     */
    public function getLengthInBytes(): int
    {
        return $this->length;
    }

    /**
     * Returns the block length (in bits)
     */
    public function getBlockLength(): int
    {
        return $this->blockSize;
    }

    /**
     * Returns the block length (in bytes)
     */
    public function getBlockLengthInBytes(): int
    {
        return $this->blockSize >> 3;
    }

    /**
     * Pads SHA3 based on the mode
     */
    private static function sha3_pad(int $padLength, int $padType): string
    {
        switch ($padType) {
            case self::PADDING_KECCAK:
                $temp = chr(0x01) . str_repeat("\0", $padLength - 1);
                $temp[$padLength - 1] = $temp[$padLength - 1] | chr(0x80);
                return $temp;
            case self::PADDING_SHAKE:
                $temp = chr(0x1F) . str_repeat("\0", $padLength - 1);
                $temp[$padLength - 1] = $temp[$padLength - 1] | chr(0x80);
                return $temp;
            //case self::PADDING_SHA3:
            default:
                // from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=36
                return $padLength == 1 ? chr(0x86) : chr(0x06) . str_repeat("\0", $padLength - 2) . chr(0x80);
        }
    }

    /**
     * Pure-PHP 32-bit implementation of SHA3
     *
     * Whereas BigInteger.php's 32-bit engine works on PHP 64-bit this 32-bit implementation
     * of SHA3 will *not* work on PHP 64-bit. This is because this implementation
     * employees bitwise NOTs and bitwise left shifts. And the round constants only work
     * on 32-bit PHP. eg. dechex(-2147483648) returns 80000000 on 32-bit PHP and
     * FFFFFFFF80000000 on 64-bit PHP. Sure, we could do bitwise ANDs but that would slow
     * things down.
     *
     * SHA512 requires BigInteger to simulate 64-bit unsigned integers because SHA2 employees
     * addition whereas SHA3 just employees bitwise operators. PHP64 only supports signed
     * 64-bit integers, which complicates addition, whereas that limitation isn't an issue
     * for SHA3.
     *
     * In https://ws680.nist.gov/publication/get_pdf.cfm?pub_id=919061#page=16 KECCAK[C] is
     * defined as "the KECCAK instance with KECCAK-f[1600] as the underlying permutation and
     * capacity c". This is relevant because, altho the KECCAK standard defines a mode
     * (KECCAK-f[800]) designed for 32-bit machines that mode is incompatible with SHA3
     */
    private static function sha3_32(string $p, int $c, int $r, int $d, int $padType): string
    {
        $block_size = $r >> 3;
        $padLength = $block_size - (strlen($p) % $block_size);
        $num_ints = $block_size >> 2;

        $p .= static::sha3_pad($padLength, $padType);

        $n = strlen($p) / $r; // number of blocks

        $s = [
            [[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
            [[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
            [[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
            [[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
            [[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
        ];

        $p = str_split($p, $block_size);

        foreach ($p as $pi) {
            $pi = unpack('V*', $pi);
            $x = $y = 0;
            for ($i = 1; $i <= $num_ints; $i += 2) {
                $s[$x][$y][0] ^= $pi[$i + 1];
                $s[$x][$y][1] ^= $pi[$i];
                if (++$y == 5) {
                    $y = 0;
                    $x++;
                }
            }
            static::processSHA3Block32($s);
        }

        $z = '';
        $i = $j = 0;
        while (strlen($z) < $d) {
            $z .= pack('V2', $s[$i][$j][1], $s[$i][$j++][0]);
            if ($j == 5) {
                $j = 0;
                $i++;
                if ($i == 5) {
                    $i = 0;
                    static::processSHA3Block32($s);
                }
            }
        }

        return $z;
    }

    /**
     * 32-bit block processing method for SHA3
     */
    private static function processSHA3Block32(array &$s): void
    {
        static $rotationOffsets = [
            [ 0,  1, 62, 28, 27],
            [36, 44,  6, 55, 20],
            [ 3, 10, 43, 25, 39],
            [41, 45, 15, 21,  8],
            [18,  2, 61, 56, 14],
        ];

        // the standards give these constants in hexadecimal notation. it's tempting to want to use
        // that same notation, here, however, we can't, because 0x80000000, on PHP32, is a positive
        // float - not the negative int that we need to be in PHP32. so we use -2147483648 instead
        static $roundConstants = [
            [0, 1],
            [0, 32898],
            [-2147483648, 32906],
            [-2147483648, -2147450880],
            [0, 32907],
            [0, -2147483647],
            [-2147483648, -2147450751],
            [-2147483648, 32777],
            [0, 138],
            [0, 136],
            [0, -2147450871],
            [0, -2147483638],
            [0, -2147450741],
            [-2147483648, 139],
            [-2147483648, 32905],
            [-2147483648, 32771],
            [-2147483648, 32770],
            [-2147483648, 128],
            [0, 32778],
            [-2147483648, -2147483638],
            [-2147483648, -2147450751],
            [-2147483648, 32896],
            [0, -2147483647],
            [-2147483648, -2147450872],
        ];

        for ($round = 0; $round < 24; $round++) {
            // theta step
            $parity = $rotated = [];
            for ($i = 0; $i < 5; $i++) {
                $parity[] = [
                    $s[0][$i][0] ^ $s[1][$i][0] ^ $s[2][$i][0] ^ $s[3][$i][0] ^ $s[4][$i][0],
                    $s[0][$i][1] ^ $s[1][$i][1] ^ $s[2][$i][1] ^ $s[3][$i][1] ^ $s[4][$i][1],
                ];
                $rotated[] = static::rotateLeft32($parity[$i], 1);
            }

            $temp = [
                [$parity[4][0] ^ $rotated[1][0], $parity[4][1] ^ $rotated[1][1]],
                [$parity[0][0] ^ $rotated[2][0], $parity[0][1] ^ $rotated[2][1]],
                [$parity[1][0] ^ $rotated[3][0], $parity[1][1] ^ $rotated[3][1]],
                [$parity[2][0] ^ $rotated[4][0], $parity[2][1] ^ $rotated[4][1]],
                [$parity[3][0] ^ $rotated[0][0], $parity[3][1] ^ $rotated[0][1]],
            ];
            for ($i = 0; $i < 5; $i++) {
                for ($j = 0; $j < 5; $j++) {
                    $s[$i][$j][0] ^= $temp[$j][0];
                    $s[$i][$j][1] ^= $temp[$j][1];
                }
            }

            $st = $s;

            // rho and pi steps
            for ($i = 0; $i < 5; $i++) {
                for ($j = 0; $j < 5; $j++) {
                    $st[(2 * $i + 3 * $j) % 5][$j] = static::rotateLeft32($s[$j][$i], $rotationOffsets[$j][$i]);
                }
            }

            // chi step
            for ($i = 0; $i < 5; $i++) {
                $s[$i][0] = [
                    $st[$i][0][0] ^ (~$st[$i][1][0] & $st[$i][2][0]),
                    $st[$i][0][1] ^ (~$st[$i][1][1] & $st[$i][2][1]),
                ];
                $s[$i][1] = [
                    $st[$i][1][0] ^ (~$st[$i][2][0] & $st[$i][3][0]),
                    $st[$i][1][1] ^ (~$st[$i][2][1] & $st[$i][3][1]),
                ];
                $s[$i][2] = [
                    $st[$i][2][0] ^ (~$st[$i][3][0] & $st[$i][4][0]),
                    $st[$i][2][1] ^ (~$st[$i][3][1] & $st[$i][4][1]),
                ];
                $s[$i][3] = [
                    $st[$i][3][0] ^ (~$st[$i][4][0] & $st[$i][0][0]),
                    $st[$i][3][1] ^ (~$st[$i][4][1] & $st[$i][0][1]),
                ];
                $s[$i][4] = [
                    $st[$i][4][0] ^ (~$st[$i][0][0] & $st[$i][1][0]),
                    $st[$i][4][1] ^ (~$st[$i][0][1] & $st[$i][1][1]),
                ];
            }

            // iota step
            $s[0][0][0] ^= $roundConstants[$round][0];
            $s[0][0][1] ^= $roundConstants[$round][1];
        }
    }

    /**
     * Rotate 32-bit int
     */
    private static function rotateLeft32(array $x, int $shift): array
    {
        if ($shift < 32) {
            [$hi, $lo] = $x;
        } else {
            $shift -= 32;
            [$lo, $hi] = $x;
        }

        $mask = -1 ^ (-1 << $shift);
        return [
            ($hi << $shift) | (($lo >> (32 - $shift)) & $mask),
            ($lo << $shift) | (($hi >> (32 - $shift)) & $mask),
        ];
    }

    /**
     * Pure-PHP 64-bit implementation of SHA3
     */
    private static function sha3_64(string $p, int $c, int $r, int $d, int $padType): string
    {
        $block_size = $r >> 3;
        $padLength = $block_size - (strlen($p) % $block_size);
        $num_ints = $block_size >> 2;

        $p .= static::sha3_pad($padLength, $padType);

        $n = strlen($p) / $r; // number of blocks

        $s = [
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];

        $p = str_split($p, $block_size);

        foreach ($p as $pi) {
            $pi = unpack('P*', $pi);
            $x = $y = 0;
            foreach ($pi as $subpi) {
                $s[$x][$y++] ^= $subpi;
                if ($y == 5) {
                    $y = 0;
                    $x++;
                }
            }
            static::processSHA3Block64($s);
        }

        $z = '';
        $i = $j = 0;
        while (strlen($z) < $d) {
            $z .= pack('P', $s[$i][$j++]);
            if ($j == 5) {
                $j = 0;
                $i++;
                if ($i == 5) {
                    $i = 0;
                    static::processSHA3Block64($s);
                }
            }
        }

        return $z;
    }

    /**
     * 64-bit block processing method for SHA3
     */
    private static function processSHA3Block64(array &$s): void
    {
        static $rotationOffsets = [
            [ 0,  1, 62, 28, 27],
            [36, 44,  6, 55, 20],
            [ 3, 10, 43, 25, 39],
            [41, 45, 15, 21,  8],
            [18,  2, 61, 56, 14],
        ];

        static $roundConstants = [
            1,
            32898,
            -9223372036854742902,
            -9223372034707259392,
            32907,
            2147483649,
            -9223372034707259263,
            -9223372036854743031,
            138,
            136,
            2147516425,
            2147483658,
            2147516555,
            -9223372036854775669,
            -9223372036854742903,
            -9223372036854743037,
            -9223372036854743038,
            -9223372036854775680,
            32778,
            -9223372034707292150,
            -9223372034707259263,
            -9223372036854742912,
            2147483649,
            -9223372034707259384,
        ];

        for ($round = 0; $round < 24; $round++) {
            // theta step
            $parity = [];
            for ($i = 0; $i < 5; $i++) {
                $parity[] = $s[0][$i] ^ $s[1][$i] ^ $s[2][$i] ^ $s[3][$i] ^ $s[4][$i];
            }
            $temp = [
                $parity[4] ^ static::rotateLeft64($parity[1], 1),
                $parity[0] ^ static::rotateLeft64($parity[2], 1),
                $parity[1] ^ static::rotateLeft64($parity[3], 1),
                $parity[2] ^ static::rotateLeft64($parity[4], 1),
                $parity[3] ^ static::rotateLeft64($parity[0], 1),
            ];
            for ($i = 0; $i < 5; $i++) {
                for ($j = 0; $j < 5; $j++) {
                    $s[$i][$j] ^= $temp[$j];
                }
            }

            $st = $s;

            // rho and pi steps
            for ($i = 0; $i < 5; $i++) {
                for ($j = 0; $j < 5; $j++) {
                    $st[(2 * $i + 3 * $j) % 5][$j] = static::rotateLeft64($s[$j][$i], $rotationOffsets[$j][$i]);
                }
            }

            // chi step
            for ($i = 0; $i < 5; $i++) {
                $s[$i] = [
                    $st[$i][0] ^ (~$st[$i][1] & $st[$i][2]),
                    $st[$i][1] ^ (~$st[$i][2] & $st[$i][3]),
                    $st[$i][2] ^ (~$st[$i][3] & $st[$i][4]),
                    $st[$i][3] ^ (~$st[$i][4] & $st[$i][0]),
                    $st[$i][4] ^ (~$st[$i][0] & $st[$i][1]),
                ];
            }

            // iota step
            $s[0][0] ^= $roundConstants[$round];
        }
    }

    /**
     * Rotate 64-bit int
     */
    private static function rotateLeft64(int $x, int $shift): int
    {
        $mask = -1 ^ (-1 << $shift);
        return ($x << $shift) | (($x >> (64 - $shift)) & $mask);
    }

    /**
     *  OMAC Padding
     *
     * @link https://www.rfc-editor.org/rfc/rfc4493.html#section-2.4
     */
    private static function OMAC_padding($m, $length)
    {
        $count = $length - strlen($m) - 1;
        return "$m\x80" . str_repeat("\0", $count);
    }

    /**
     *  __toString() magic method
     */
    public function __toString()
    {
        return $this->getHash();
    }

    // from https://www.rfc-editor.org/rfc/rfc7292#appendix-B.2
    // this is mostly the same as SymmetricKey::setPassword()'s implementation of pkcs12
    public function setPassword(string $password, string $salt, int $iterationCount): void
    {
        if (!isset($this->blockSize)) {
            throw new UnsupportedAlgorithmException($this->hashParam . ' cannot be used with the PKCS#12 KDF');
        }

        $password = "\0" . chunk_split($password, 1, "\0") . "\0";

        $u = $this->length << 3;
        $v = $this->blockSize >> 3;
        $saltLength = strlen($salt);
        $passLength = strlen($password);

        $d = str_repeat("\3", $v);

        $s = $saltLength ? str_repeat($salt, (int) ceil($v / $saltLength)) : '';
        $s = substr($s, 0, $v);

        $p = $passLength ? str_repeat($password, (int) ceil($v / $passLength)) : '';
        $p = substr($p, 0, $v);

        $i = $s . $p;

        $key = self::pkcs12helper($this->length, $this, $i, $d, $iterationCount);
        $this->setKey($key);
    }
}
