<?php

/**
 * OpenSSH Formatted DSA Key Handler
 *
 * PHP version 5
 *
 * Place in $HOME/.ssh/authorized_keys
 *
 * @category  Crypt
 * @package   DSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\DSA\Keys;

use ParagonIE\ConstantTime\Base64;
use phpseclib\Math\BigInteger;
use phpseclib\Common\Functions\Strings;
use phpseclib\Crypt\Common\Keys\OpenSSH as Progenitor;

/**
 * OpenSSH Formatted DSA Key Handler
 *
 * @package DSA
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
        $key = parent::load($key, 'ssh-dss');

        $result = Strings::unpackSSH2('iiii', $key);
        if ($result === false) {
            throw new \UnexpectedValueException('Key appears to be malformed');
        }
        list($p, $q, $g, $y) = $result;

        $comment = parent::getComment($key);

        return compact('p', 'q', 'g', 'y', 'comment');
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $p
     * @param \phpseclib\Math\BigInteger $q
     * @param \phpseclib\Math\BigInteger $g
     * @param \phpseclib\Math\BigInteger $y
     * @return string
     */
    public static function savePublicKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y)
    {
        if ($q->getLength() != 160) {
            throw new \InvalidArgumentException('SSH only supports keys with an N (length of Group Order q) of 160');
        }

        // from <http://tools.ietf.org/html/rfc4253#page-15>:
        // string    "ssh-dss"
        // mpint     p
        // mpint     q
        // mpint     g
        // mpint     y
        $DSAPublicKey = Strings::packSSH2('siiii', 'ssh-dss', $p, $q, $g, $y);

        if (self::$binary) {
            return $DSAPublicKey;
        }

        $DSAPublicKey = 'ssh-dss ' . Base64::encode($DSAPublicKey) . ' ' . self::$comment;

        return $DSAPublicKey;
    }
}
