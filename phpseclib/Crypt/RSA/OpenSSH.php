<?php
/**
 * OpenSSH Formatted RSA Key Handler
 *
 * PHP version 5
 *
 * Place in $HOME/.ssh/authorized_keys
 *
 * @category  Crypt
 * @package   RSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\RSA;

use phpseclib\Math\BigInteger;

/**
 * XML Formatted RSA Key Handler
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class OpenSSH
{
    /**
     * Default comment
     *
     * @var string
     * @access private
     */
    static $comment = 'phpseclib-generated-key';

    /**
     * Sets the default comment
     *
     * @access public
     * @param string $comment
     */
    static function setEncryptionAlgorithm($comment)
    {
        self::$comment = $comment;
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
       $parts = explode(' ', $key, 3);

       $key = isset($parts[1]) ? base64_decode($parts[1]) : false;
       if ($key === false) {
           return false;
       }

       $comment = isset($parts[2]) ? $parts[2] : false;

       $cleanup = substr($key, 0, 11) == "\0\0\0\7ssh-rsa";

       if (strlen($key) <= 4) {
           return false;
       }
       extract(unpack('Nlength', self::_string_shift($key, 4)));
       $publicExponent = new BigInteger(self::_string_shift($key, $length), -256);
       if (strlen($key) <= 4) {
           return false;
       }
       extract(unpack('Nlength', self::_string_shift($key, 4)));
       $modulus = new BigInteger(self::_string_shift($key, $length), -256);

       if ($cleanup && strlen($key)) {
           if (strlen($key) <= 4) {
               return false;
           }
           extract(unpack('Nlength', self::_string_shift($key, 4)));
           $realModulus = new BigInteger(self::_string_shift($key, $length), -256);
           return strlen($key) ? false : array(
               'isPublicKey' => true,
               'modulus' => $realModulus,
               'publicExponent' => $modulus,
               'comment' => $comment
           );
       } else {
           return strlen($key) ? false : array(
               'isPublicKey' => true,
               'modulus' => $modulus,
               'publicExponent' => $publicExponent,
               'comment' => $comment
           );
       }
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $n
     * @param \phpseclib\Math\BigInteger $e
     * @return string
     */
    function savePublicKey(BigInteger $n, BigInteger $e)
    {
        $publicExponent = $e->toBytes(true);
        $modulus = $n->toBytes(true);

        // from <http://tools.ietf.org/html/rfc4253#page-15>:
        // string    "ssh-rsa"
        // mpint     e
        // mpint     n
        $RSAPublicKey = pack('Na*Na*Na*', strlen('ssh-rsa'), 'ssh-rsa', strlen($publicExponent), $publicExponent, strlen($modulus), $modulus);
        $RSAPublicKey = 'ssh-rsa ' . base64_encode($RSAPublicKey) . ' ' . self::$comment;

        return $RSAPublicKey;
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