<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Pure-PHP implementation of keyed-hash message authentication codes (HMACs).
 *
 * Uses hash() or mhash() if available and an internal implementation, otherwise.  Currently supports md5 and sha1.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA  02111-1307  USA
 *
 * @category   Crypt
 * @package    Crypt_HMAC
 * @author     Jim Wigginton <terrafrost@php.net>
 * @copyright  MMVII Jim Wigginton
 * @license    http://www.gnu.org/licenses/lgpl.txt
 * @version    $Id: HMAC.php,v 1.3 2007-09-23 04:41:39 terrafrost Exp $
 * @link       http://phpseclib.sourceforge.net
 */

/**#@+
 * @access private
 * @see Crypt_HMAC::Crypt_HMAC()
 */
/**
 * Toggles the internal implementation
 */
define('CRYPT_HMAC_MODE_INTERNAL', 1);
/**
 * Toggles the mhash() implementation, which has been deprecated on PHP 5.3.0+.
 */
define('CRYPT_HMAC_MODE_MHASH',    2);
/**
 * Toggles the hash() implementation, which works on PHP 5.1.2+.
 */
define('CRYPT_HMAC_MODE_HASH',     3);
/**#@-*/

/**
 * Pure-PHP implementation of keyed-hash message authentication codes (HMACs).
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @version 0.1.0
 * @access  public
 * @package Crypt_HMAC
 */
class Crypt_HMAC {
    /**
     * Byte-length of compression blocks
     *
     * The following URL provides more information:
     *
     * {@link http://tools.ietf.org/html/rfc2104#section-2 http://tools.ietf.org/html/rfc2104#section-2}
     *
     * @see Crypt_HMAC::setHash()
     * @var Integer
     * @access private
     */
    var $b;

    /**
     * Byte-length of hash outputs
     *
     * @see Crypt_HMAC::setHash()
     * @var Integer
     * @access private
     */
    var $l;

    /**
     * Hash Algorithm
     *
     * @see Crypt_HMAC::setHash()
     * @var String
     * @access private
     */
    var $hash;

    /**
     * Key
     *
     * @see Crypt_HMAC::setKey()
     * @var String
     * @access private
     */
    var $key = '';

    /**
     * Outer XOR
     *
     * @see Crypt_HMAC::setKey()
     * @var String
     * @access private
     */
    var $opad;

    /**
     * Inner XOR
     *
     * @see Crypt_HMAC::setKey()
     * @var String
     * @access private
     */
    var $ipad;

    /**
     * Final HMAC Length
     *
     * @see Crypt_HMAC::hmac()
     * @var String
     * @access private
     */
    var $length = 0;

    /**
     * Default Constructor.
     *
     * @return Crypt_HMAC
     * @access public
     */
    function Crypt_HMAC()
    {
        if ( !defined('CRYPT_HMAC_MODE') ) {
            switch (true) {
                case extension_loaded('hash'):
                    define('CRYPT_HMAC_MODE', CRYPT_HMAC_MODE_HASH);
                    break;
                case extension_loaded('mhash'):
                    define('CRYPT_HMAC_MODE', CRYPT_HMAC_MODE_MHASH);
                    break;
                default:
                    define('CRYPT_HMAC_MODE', CRYPT_HMAC_MODE_INTERNAL);
            }
        }

        $this->setHash('sha1');
    }

    /**
     * Sets the key.
     *
     * @access public
     * @param String $key
     */
    function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * Sets the hash function.
     *
     * Currently, only 'sha1' and 'md5' are supported.  If you do not supply a valid $hash, 'sha1' will be used.
     *
     * @access public
     * @param String $hash
     */
    function setHash($hash)
    {
        switch ($hash) {
            case 'md5-96':
            case 'sha1-96':
                $this->length = 12;
        }

        switch (CRYPT_HMAC_MODE) {
            case CRYPT_HMAC_MODE_MHASH:
                switch ($hash) {
                    case 'md5':
                    case 'md5-96':
                        $this->hash = MHASH_MD5;
                        break;
                    case 'sha1':
                    case 'sha1-96':
                    default:
                        $this->hash = MHASH_SHA1;
                }
                return;
            case CRYPT_HMAC_MODE_HASH:
                switch ($hash) {
                    case 'md5':
                    case 'md5-96':
                        $this->hash = 'md5';
                        return;
                    case 'sha1':
                    case 'sha1-96':
                    default:
                        $this->hash = 'sha1';
                }
                return;
        }

        switch ($hash) {
            case 'md5':
            case 'md5-96':
                 $this->b = 64;
                 $this->l = 16;
                 $this->hash = 'md5';
                 break;
            case 'sha1':
            case 'sha1-96':
            default:
                 $this->b = 64;
                 $this->l = 20;
                 $this->hash = 'sha1';
        }

        $this->ipad = str_repeat(chr(0x36), $this->b);
        $this->opad = str_repeat(chr(0x5C), $this->b);
    }

    /**
     * Compute the HMAC.
     *
     * @access public
     * @param String $text
     */
    function hmac($text)
    {
        switch (CRYPT_HMAC_MODE) {
            case CRYPT_HMAC_MODE_MHASH:
                $hmac = mhash($this->hash, $text, $this->key);
                break;
            case CRYPT_HMAC_MODE_HASH:
                $hmac = hash_hmac($this->hash, $text, $this->key, true);
                break;
            case CRYPT_HMAC_MODE_INTERNAL:
                $hash = $this->hash;

                $key = strlen($this->key) > $this->b ? $this->hash($this->key) : $this->key;
                $key = str_pad($key, $this->b, chr(0)); // step 1
                $temp = $this->ipad ^ $key;             // step 2
                $temp.= $text;                          // step 3
                $temp = pack('H*', $hash($temp));       // step 4
                $hmac = $this->opad ^ $key;             // step 5
                $hmac.= $temp;                          // step 6
                $hmac = pack('H*', $hash($hmac));       // step 7
        }

        return $this->length ? substr($hmac, 0, $this->length) : $hmac;
    }
}