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
use phpseclib\Common\Functions\Strings;

/**
 * @package Hash
 * @author  Jim Wigginton <terrafrost@php.net>
 * @author  Andreas Fischer <bantu@phpbb.com>
 * @access  public
 */
class Hash
{
    /**#@+
     * Padding Types
     *
     * @access private
     */
    //const PADDING_KECCAK = 1;
    const PADDING_SHA3 = 2;
    const PADDING_SHAKE = 3;
    /**#@-*/

    /**
     * Padding Type
     *
     * Only used by SHA3
     *
     * @var int
     * @access private
     */
    private $paddingType = 0;

    /**
     * Hash Parameter
     *
     * @see self::setHash()
     * @var int
     * @access private
     */
    private $hashParam;

    /**
     * Byte-length of hash output (Internal HMAC)
     *
     * @see self::setHash()
     * @var int
     * @access private
     */
    private $length;

    /**
     * Hash Algorithm
     *
     * @see self::setHash()
     * @var string
     * @access private
     */
    private $hash;

    /**
     * Key
     *
     * @see self::setKey()
     * @var string
     * @access private
     */
    private $key = false;

    /**
     * Hash Parameters
     *
     * @var array
     * @access private
     */
    private $parameters = [];

    /**
     * Computed Key
     *
     * @see self::_computeKey()
     * @var string
     * @access private
     */
    private $computedKey = false;

    /**
     * Outer XOR (Internal HMAC)
     *
     * Used only for sha512/*
     *
     * @see self::hash()
     * @var string
     * @access private
     */
    private $opad;

    /**
     * Inner XOR (Internal HMAC)
     *
     * Used only for sha512/*
     *
     * @see self::hash()
     * @var string
     * @access private
     */
    private $ipad;

    /**
     * Default Constructor.
     *
     * @param string $hash
     * @access public
     */
    public function __construct($hash = 'sha256')
    {
        $this->setHash($hash);
    }

    /**
     * Sets the key for HMACs
     *
     * Keys can be of any length.
     *
     * @access public
     * @param string $key
     */
    public function setKey($key = false)
    {
        $this->key = $key;
        $this->computeKey();
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
     *
     * @access private
     */
    private function computeKey()
    {
        if ($this->key === false) {
            $this->computedKey = false;
            return;
        }

        if (strlen($this->key) <= $this->getBlockLengthInBytes()) {
            $this->computedKey = $this->key;
            return;
        }

        $this->computedKey = is_array($this->hash) ?
            call_user_func($this->hash, $this->key) :
            hash($this->hash, $this->key, true);
    }

    /**
     * Gets the hash function.
     *
     * As set by the constructor or by the setHash() method.
     *
     * @access public
     * @return string
     */
    public function getHash()
    {
        return $this->hashParam;
    }

    /**
     * Sets the hash function.
     *
     * @access public
     * @param string $hash
     */
    public function setHash($hash)
    {
        $this->hashParam = $hash = strtolower($hash);
        switch ($hash) {
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

        if (in_array(substr($hash, 0, 5), ['sha3-', 'shake'])) {
            // PHP 7.1.0 introduced support for "SHA3 fixed mode algorithms":
            // http://php.net/ChangeLog-7.php#7.1.0
            if (version_compare(PHP_VERSION, '7.1.0') < 0 || substr($hash, 0,5) == 'shake') {
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
                    'padding' => $this->paddingType
                ];
                $hash = ['phpseclib\Crypt\Hash', PHP_INT_SIZE == 8 ? 'sha3_64' : 'sha3_32'];
            }
        }

        if ($hash == 'sha512/224' || $hash == 'sha512/256') {
            // PHP 7.1.0 introduced sha512/224 and sha512/256 support:
            // http://php.net/ChangeLog-7.php#7.1.0
            if (version_compare(PHP_VERSION, '7.1.0') < 0) {
                // from http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf#page=24
                $initial = $hash == 'sha512/256' ?
                    [
                        '22312194FC2BF72C', '9F555FA3C84C64C2', '2393B86B6F53B151', '963877195940EABD',
                        '96283EE2A88EFFE3', 'BE5E1E2553863992', '2B0199FC2C85B8AA', '0EB72DDC81C52CA2'
                    ] :
                    [
                        '8C3D37C819544DA2', '73E1996689DCD4D6', '1DFAB7AE32FF9C82', '679DD514582F9FCF',
                        '0F6D2B697BD44DA8', '77E36F7304C48942', '3F9D85A86A1D36C8', '1112E6AD91D692A1'
                    ];
                for ($i = 0; $i < 8; $i++) {
                    $initial[$i] = new BigInteger($initial[$i], 16);
                    $initial[$i]->setPrecision(64);
                }

                $this->parameters = compact('initial');

                $hash = ['phpseclib\Crypt\Hash', 'sha512'];
            }
        }

        if (is_array($hash)) {
            $b = $this->blockSize >> 3;
            $this->ipad = str_repeat(chr(0x36), $b);
            $this->opad = str_repeat(chr(0x5C), $b);
        }

        $this->hash = $hash;

        $this->computeKey();
    }

    /**
     * Compute the HMAC.
     *
     * @access public
     * @param string $text
     * @return string
     */
    public function hash($text)
    {
        if (is_array($this->hash)) {
            if (empty($this->key) || !is_string($this->key)) {
                return substr(call_user_func($this->hash, $text, ...array_values($this->parameters)), 0, $this->length);
            }

            // SHA3 HMACs are discussed at https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=30

            $key    = str_pad($this->computedKey, $b, chr(0));
            $temp   = $this->ipad ^ $key;
            $temp  .= $text;
            $temp   = substr(call_user_func($this->hash, $temp, ...array_values($this->parameters)), 0, $this->length);
            $output = $this->opad ^ $key;
            $output.= $temp;
            $output = call_user_func($this->hash, $output, ...array_values($this->parameters));

            return substr($output, 0, $this->length);
        }

        $output = !empty($this->key) || is_string($this->key) ?
            hash_hmac($this->hash, $text, $this->computedKey, true) :
            hash($this->hash, $text, true);

        return strlen($output) > $this->length
            ? substr($output, 0, $this->length)
            : $output;
    }

    /**
     * Returns the hash length (in bits)
     *
     * @access public
     * @return int
     */
    public function getLength()
    {
        return $this->length << 3;
    }

    /**
     * Returns the hash length (in bytes)
     *
     * @access public
     * @return int
     */
    public function getLengthInBytes()
    {
        return $this->length;
    }

    /**
     * Returns the block length (in bits)
     *
     * @access public
     * @return int
     */
    public function getBlockLength()
    {
        return $this->blockSize;
    }

    /**
     * Returns the block length (in bytes)
     *
     * @access public
     * @return int
     */
    public function getBlockLengthInBytes()
    {
        return $this->blockSize >> 3;
    }

    /**
     * Pads SHA3 based on the mode
     *
     * @access private
     * @param int $padLength
     * @param int $padType
     * @return string
     */
    private static function sha3_pad($padLength, $padType)
    {
        switch ($padType) {
            //case self::PADDING_KECCAK:
            //    $temp = chr(0x06) . str_repeat("\0", $padLength - 1);
            //    $temp[$padLength - 1] = $temp[$padLength - 1] | chr(0x80);
            //    return $temp
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
     *
     * @access private
     * @param string $p
     * @param int $c
     * @param int $r
     * @param int $d
     * @param int $padType
     */
    private static function sha3_32($p, $c, $r, $d, $padType)
    {
        $block_size = $r >> 3;
        $padLength = $block_size - (strlen($p) % $block_size);
        $num_ints = $block_size >> 2;

        $p.= static::sha3_pad($padLength, $padType);

        $n = strlen($p) / $r; // number of blocks

        $s = [
            [[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
            [[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
            [[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
            [[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
            [[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]]
        ];

        $p = str_split($p, $block_size);

        foreach ($p as $pi) {
            $pi = unpack('V*', $pi);
            $x = $y = 0;
            for ($i = 1; $i <= $num_ints; $i+=2) {
                $s[$x][$y][0]^= $pi[$i + 1];
                $s[$x][$y][1]^= $pi[$i];
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
            $z.= pack('V2', $s[$i][$j][1], $s[$i][$j++][0]);
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
     *
     * @access private
     * @param array $s
     */
    private static function processSHA3Block32(&$s)
    {
        static $rotationOffsets = [
            [ 0,  1, 62, 28, 27],
            [36, 44,  6, 55, 20],
            [ 3, 10, 43, 25, 39],
            [41, 45, 15, 21,  8],
            [18,  2, 61, 56, 14]
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
            [-2147483648, -2147450872]
        ];

        for ($round = 0; $round < 24; $round++) {
            // theta step
            $parity = $rotated = [];
            for ($i = 0; $i < 5; $i++) {
                $parity[] = [
                    $s[0][$i][0] ^ $s[1][$i][0] ^ $s[2][$i][0] ^ $s[3][$i][0] ^ $s[4][$i][0],
                    $s[0][$i][1] ^ $s[1][$i][1] ^ $s[2][$i][1] ^ $s[3][$i][1] ^ $s[4][$i][1]
                ];
                $rotated[] = static::rotateLeft32($parity[$i], 1);
            }

            $temp = [
                [$parity[4][0] ^ $rotated[1][0], $parity[4][1] ^ $rotated[1][1]],
                [$parity[0][0] ^ $rotated[2][0], $parity[0][1] ^ $rotated[2][1]],
                [$parity[1][0] ^ $rotated[3][0], $parity[1][1] ^ $rotated[3][1]],
                [$parity[2][0] ^ $rotated[4][0], $parity[2][1] ^ $rotated[4][1]],
                [$parity[3][0] ^ $rotated[0][0], $parity[3][1] ^ $rotated[0][1]]
            ];
            for ($i = 0; $i < 5; $i++) {
                for ($j = 0; $j < 5; $j++) {
                    $s[$i][$j][0]^= $temp[$j][0];
                    $s[$i][$j][1]^= $temp[$j][1];
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
                    $st[$i][0][1] ^ (~$st[$i][1][1] & $st[$i][2][1])
                ];
                $s[$i][1] = [
                    $st[$i][1][0] ^ (~$st[$i][2][0] & $st[$i][3][0]),
                    $st[$i][1][1] ^ (~$st[$i][2][1] & $st[$i][3][1])
                ];
                $s[$i][2] = [
                    $st[$i][2][0] ^ (~$st[$i][3][0] & $st[$i][4][0]),
                    $st[$i][2][1] ^ (~$st[$i][3][1] & $st[$i][4][1])
                ];
                $s[$i][3] = [
                    $st[$i][3][0] ^ (~$st[$i][4][0] & $st[$i][0][0]),
                    $st[$i][3][1] ^ (~$st[$i][4][1] & $st[$i][0][1])
                ];
                $s[$i][4] = [
                    $st[$i][4][0] ^ (~$st[$i][0][0] & $st[$i][1][0]),
                    $st[$i][4][1] ^ (~$st[$i][0][1] & $st[$i][1][1])
                ];
            }

            // iota step
            $s[0][0][0]^= $roundConstants[$round][0];
            $s[0][0][1]^= $roundConstants[$round][1];
        }
    }

    /**
     * Rotate 32-bit int
     *
     * @access private
     * @param array $x
     * @param int $shift
     */
    private static function rotateLeft32($x, $shift)
    {
        if ($shift < 32) {
            list($hi, $lo) = $x;
        } else {
            $shift-= 32;
            list($lo, $hi) = $x;
        }

        return [
            ($hi << $shift) | (($lo >> (32 - $shift)) & (1 << $shift) - 1),
            ($lo << $shift) | (($hi >> (32 - $shift)) & (1 << $shift) - 1)
        ];
    }

    /**
     * Pure-PHP 64-bit implementation of SHA3
     *
     * @access private
     * @param string $p
     * @param int $c
     * @param int $r
     * @param int $d
     * @param int $padType
     */
    private static function sha3_64($p, $c, $r, $d, $padType)
    {
        $block_size = $r >> 3;
        $padLength = $block_size - (strlen($p) % $block_size);
        $num_ints = $block_size >> 2;

        $p.= static::sha3_pad($padLength, $padType);

        $n = strlen($p) / $r; // number of blocks

        $s = [
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0]
        ];

        $p = str_split($p, $block_size);

        foreach ($p as $pi) {
            $pi = unpack('P*', $pi);
            $x = $y = 0;
            foreach ($pi as $subpi) {
                $s[$x][$y++]^= $subpi;
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
            $z.= pack('P', $s[$i][$j++]);
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
     *
     * @access private
     * @param array $s
     */
    private static function processSHA3Block64(&$s)
    {
        static $rotationOffsets = [
            [ 0,  1, 62, 28, 27],
            [36, 44,  6, 55, 20],
            [ 3, 10, 43, 25, 39],
            [41, 45, 15, 21,  8],
            [18,  2, 61, 56, 14]
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
            -9223372034707259384
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
                $parity[3] ^ static::rotateLeft64($parity[0], 1)
            ];
            for ($i = 0; $i < 5; $i++) {
                for ($j = 0; $j < 5; $j++) {
                    $s[$i][$j]^= $temp[$j];
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
                    $st[$i][4] ^ (~$st[$i][0] & $st[$i][1])
                ];
            }

            // iota step
            $s[0][0]^= $roundConstants[$round];
        }
    }

    /**
     * Rotate 64-bit int
     *
     * @access private
     * @param int $x
     * @param int $shift
     */
    private static function rotateLeft64($x, $shift)
    {
        return ($x << $shift) | (($x >> (64 - $shift)) & ((1 << $shift) - 1));
    }

    /**
     * Pure-PHP implementation of SHA512
     *
     * @access private
     * @param string $m
     * @param array $hash
     * @return string
     */
    private static function sha512($m, $hash)
    {
        static $k;

        if (!isset($k)) {
            // Initialize table of round constants
            // (first 64 bits of the fractional parts of the cube roots of the first 80 primes 2..409)
            $k = [
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
            ];

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
            $w = [];
            for ($i = 0; $i < 16; $i++) {
                $temp = new BigInteger(Strings::shift($chunk, 8), 256);
                $temp->setPrecision(64);
                $w[] = $temp;
            }

            // Extend the sixteen 32-bit words into eighty 32-bit words
            for ($i = 16; $i < 80; $i++) {
                $temp = [
                          $w[$i - 15]->bitwise_rightRotate(1),
                          $w[$i - 15]->bitwise_rightRotate(8),
                          $w[$i - 15]->bitwise_rightShift(7)
                ];
                $s0 = $temp[0]->bitwise_xor($temp[1]);
                $s0 = $s0->bitwise_xor($temp[2]);
                $temp = [
                          $w[$i - 2]->bitwise_rightRotate(19),
                          $w[$i - 2]->bitwise_rightRotate(61),
                          $w[$i - 2]->bitwise_rightShift(6)
                ];
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
                $temp = [
                    $a->bitwise_rightRotate(28),
                    $a->bitwise_rightRotate(34),
                    $a->bitwise_rightRotate(39)
                ];
                $s0 = $temp[0]->bitwise_xor($temp[1]);
                $s0 = $s0->bitwise_xor($temp[2]);
                $temp = [
                    $a->bitwise_and($b),
                    $a->bitwise_and($c),
                    $b->bitwise_and($c)
                ];
                $maj = $temp[0]->bitwise_xor($temp[1]);
                $maj = $maj->bitwise_xor($temp[2]);
                $t2 = $s0->add($maj);

                $temp = [
                    $e->bitwise_rightRotate(14),
                    $e->bitwise_rightRotate(18),
                    $e->bitwise_rightRotate(41)
                ];
                $s1 = $temp[0]->bitwise_xor($temp[1]);
                $s1 = $s1->bitwise_xor($temp[2]);
                $temp = [
                    $e->bitwise_and($f),
                    $g->bitwise_and($e->bitwise_not())
                ];
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
            $hash = [
                $hash[0]->add($a),
                $hash[1]->add($b),
                $hash[2]->add($c),
                $hash[3]->add($d),
                $hash[4]->add($e),
                $hash[5]->add($f),
                $hash[6]->add($g),
                $hash[7]->add($h)
            ];
        }

        // Produce the final hash value (big-endian)
        // (\phpseclib\Crypt\Hash::hash() trims the output for hashes but not for HMACs.  as such, we trim the output here)
        $temp = $hash[0]->toBytes() . $hash[1]->toBytes() . $hash[2]->toBytes() . $hash[3]->toBytes() .
                $hash[4]->toBytes() . $hash[5]->toBytes() . $hash[6]->toBytes() . $hash[7]->toBytes();

        return $temp;
    }
}
