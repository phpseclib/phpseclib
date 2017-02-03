<?php

/**
 * PuTTY Formatted RSA Key Handler
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
use phpseclib\Crypt\AES;
use phpseclib\Crypt\Hash;
use phpseclib\Math\BigInteger;
use phpseclib\Common\Functions\Strings;

/**
 * PuTTY Formatted RSA Key Handler
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class PuTTY
{
    /**
     * Default comment
     *
     * @var string
     * @access private
     */
    private static $comment = 'phpseclib-generated-key';

    /**
     * Sets the default comment
     *
     * @access public
     * @param string $comment
     */
    public static function setComment($comment)
    {
        self::$comment = str_replace(["\r", "\n"], '', $comment);
    }

    /**
     * Generate a symmetric key for PuTTY keys
     *
     * @access public
     * @param string $password
     * @param string $iv
     * @param int $length
     * @return string
     */
    public static function generateSymmetricKey($password, $length)
    {
        $symkey = '';
        $sequence = 0;
        while (strlen($symkey) < $length) {
            $temp = pack('Na*', $sequence++, $password);
            $symkey.= Hex::decode(sha1($temp));
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
    public static function load($key, $password = '')
    {
        if (!is_string($key)) {
            return false;
        }

        static $one;
        if (!isset($one)) {
            $one = new BigInteger(1);
        }

        if (strpos($key, 'BEGIN SSH2 PUBLIC KEY')) {
            $data = preg_split('#[\r\n]+#', $key);
            $data = array_splice($data, 2, -1);
            $data = implode('', $data);

            $components = OpenSSH::load($data);
            if ($components === false) {
                return false;
            }

            if (!preg_match('#Comment: "(.+)"#', $key, $matches)) {
                return false;
            }
            $components['comment'] = str_replace(['\\\\', '\"'], ['\\', '"'], $matches[1]);

            return $components;
        }

        $components = ['isPublicKey' => false];
        $key = preg_split('#\r\n|\r|\n#', $key);
        $type = trim(preg_replace('#PuTTY-User-Key-File-2: (.+)#', '$1', $key[0]));
        if ($type != 'ssh-rsa') {
            return false;
        }
        $encryption = trim(preg_replace('#Encryption: (.+)#', '$1', $key[1]));
        $components['comment'] = trim(preg_replace('#Comment: (.+)#', '$1', $key[2]));

        $publicLength = trim(preg_replace('#Public-Lines: (\d+)#', '$1', $key[3]));
        $public = Base64::decode(implode('', array_map('trim', array_slice($key, 4, $publicLength))));
        $public = substr($public, 11);
        extract(unpack('Nlength', Strings::shift($public, 4)));
        $components['publicExponent'] = new BigInteger(Strings::shift($public, $length), -256);
        extract(unpack('Nlength', Strings::shift($public, 4)));
        $components['modulus'] = new BigInteger(Strings::shift($public, $length), -256);

        $privateLength = trim(preg_replace('#Private-Lines: (\d+)#', '$1', $key[$publicLength + 4]));
        $private = Base64::decode(implode('', array_map('trim', array_slice($key, $publicLength + 5, $privateLength))));

        switch ($encryption) {
            case 'aes256-cbc':
                $symkey = static::generateSymmetricKey($password, 32);
                $crypto = new AES(AES::MODE_CBC);
        }

        if ($encryption != 'none') {
            $crypto->setKey($symkey);
            $crypto->setIV(str_repeat("\0", $crypto->getBlockLength() >> 3));
            $crypto->disablePadding();
            $private = $crypto->decrypt($private);
        }

        extract(unpack('Nlength', Strings::shift($private, 4)));
        if (strlen($private) < $length) {
            return false;
        }
        $components['privateExponent'] = new BigInteger(Strings::shift($private, $length), -256);
        extract(unpack('Nlength', Strings::shift($private, 4)));
        if (strlen($private) < $length) {
            return false;
        }
        $components['primes'] = [1 => new BigInteger(Strings::shift($private, $length), -256)];
        extract(unpack('Nlength', Strings::shift($private, 4)));
        if (strlen($private) < $length) {
            return false;
        }
        $components['primes'][] = new BigInteger(Strings::shift($private, $length), -256);

        $temp = $components['primes'][1]->subtract($one);
        $components['exponents'] = [1 => $components['publicExponent']->modInverse($temp)];
        $temp = $components['primes'][2]->subtract($one);
        $components['exponents'][] = $components['publicExponent']->modInverse($temp);

        extract(unpack('Nlength', Strings::shift($private, 4)));
        if (strlen($private) < $length) {
            return false;
        }
        $components['coefficients'] = [2 => new BigInteger(Strings::shift($private, $length), -256)];

        return $components;
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
    public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, $primes, $exponents, $coefficients, $password = '')
    {
        if (count($primes) != 2) {
            return false;
        }

        $raw = [
            'modulus' => $n->toBytes(true),
            'publicExponent' => $e->toBytes(true),
            'privateExponent' => $d->toBytes(true),
            'prime1' => $primes[1]->toBytes(true),
            'prime2' => $primes[2]->toBytes(true),
            'exponent1' => $exponents[1]->toBytes(true),
            'exponent2' => $exponents[2]->toBytes(true),
            'coefficient' => $coefficients[2]->toBytes(true)
        ];

        $key = "PuTTY-User-Key-File-2: ssh-rsa\r\nEncryption: ";
        $encryption = (!empty($password) || is_string($password)) ? 'aes256-cbc' : 'none';
        $key.= $encryption;
        $key.= "\r\nComment: " . self::$comment . "\r\n";
        $public = pack(
            'Na*Na*Na*',
            strlen('ssh-rsa'),
            'ssh-rsa',
            strlen($raw['publicExponent']),
            $raw['publicExponent'],
            strlen($raw['modulus']),
            $raw['modulus']
        );
        $source = pack(
            'Na*Na*Na*Na*',
            strlen('ssh-rsa'),
            'ssh-rsa',
            strlen($encryption),
            $encryption,
            strlen(self::$comment),
            self::$comment,
            strlen($public),
            $public
        );
        $public = Base64::encode($public);
        $key.= "Public-Lines: " . ((strlen($public) + 63) >> 6) . "\r\n";
        $key.= chunk_split($public, 64);
        $private = pack(
            'Na*Na*Na*Na*',
            strlen($raw['privateExponent']),
            $raw['privateExponent'],
            strlen($raw['prime1']),
            $raw['prime1'],
            strlen($raw['prime2']),
            $raw['prime2'],
            strlen($raw['coefficient']),
            $raw['coefficient']
        );
        if (empty($password) && !is_string($password)) {
            $source.= pack('Na*', strlen($private), $private);
            $hashkey = 'putty-private-key-file-mac-key';
        } else {
            $private.= Random::string(16 - (strlen($private) & 15));
            $source.= pack('Na*', strlen($private), $private);
            $crypto = new AES();

            $crypto->setKey(static::generateSymmetricKey($password, 32));
            $crypto->setIV(str_repeat("\0", $crypto->getBlockLength() >> 3));
            $crypto->disablePadding();
            $private = $crypto->encrypt($private);
            $hashkey = 'putty-private-key-file-mac-key' . $password;
        }

        $private = Base64::encode($private);
        $key.= 'Private-Lines: ' . ((strlen($private) + 63) >> 6) . "\r\n";
        $key.= chunk_split($private, 64);
        $hash = new Hash('sha1');
        $hash->setKey(sha1($hashkey, true));
        $key.= 'Private-MAC: ' . Hex::encode($hash->hash($source)) . "\r\n";

        return $key;
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $n
     * @param \phpseclib\Math\BigInteger $e
     * @return string
     */
    public static function savePublicKey(BigInteger $n, BigInteger $e)
    {
        $n = $n->toBytes(true);
        $e = $e->toBytes(true);

        $key = pack(
            'Na*Na*Na*',
            strlen('ssh-rsa'),
            'ssh-rsa',
            strlen($e),
            $e,
            strlen($n),
            $n
        );
        $key = "---- BEGIN SSH2 PUBLIC KEY ----\r\n" .
               'Comment: "' . str_replace(['\\', '"'], ['\\\\', '\"'], self::$comment) . "\"\r\n" .
               chunk_split(Base64::encode($key), 64) .
               '---- END SSH2 PUBLIC KEY ----';

        return $key;
    }
}
