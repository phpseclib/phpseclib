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

namespace phpseclib\Crypt\RSA\Keys;

use ParagonIE\ConstantTime\Base64;
use phpseclib\Math\BigInteger;
use phpseclib\Common\Functions\Strings;
use phpseclib\Crypt\Common\Keys\OpenSSH as Progenitor;

/**
 * OpenSSH Formatted RSA Key Handler
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class OpenSSH extends Progenitor
{
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
        $key = parent::load($key, 'ssh-rsa');

        $result = Strings::unpackSSH2('ii', $key);
        if ($result === false) {
            throw new \UnexpectedValueException('Key appears to be malformed');
        }
        list($publicExponent, $modulus) = $result;

        return [
            'isPublicKey' => true,
            'modulus' => $modulus,
            'publicExponent' => $publicExponent,
            'comment' => parent::getComment($key)
        ];
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
        $RSAPublicKey = Strings::packSSH2('sii', 'ssh-rsa', $e, $n);

        if (self::$binary) {
            return $RSAPublicKey;
        }

        $RSAPublicKey = 'ssh-rsa ' . Base64::encode($RSAPublicKey) . ' ' . self::$comment;

        return $RSAPublicKey;
    }
}
