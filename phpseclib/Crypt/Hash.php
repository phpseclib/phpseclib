<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Pure-PHP implementations of keyed-hash message authentication codes (HMACs) and various cryptographic hashing functions.
 *
 * Uses hash() or mhash() if available and an internal implementation, otherwise.  Currently supports md5, md5-96, sha1, and
 * sha1-96.  If {@link Crypt_Hash::setKey() setKey()} is called, {@link Crypt_Hash::hash() hash()} will return the HMAC as
 * as opposed to the hash.  If no valid algorithm is provided, sha1 will be used.
 *
 * PHP versions 4 and 5
 *
 * {@internal The variable names are the same as those in 
 * {@link http://tools.ietf.org/html/rfc2104#section-2 RFC2104}.}}
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include('Crypt/Hash.php');
 *
 *    $hash = new Crypt_Hash('sha1');
 *
 *    $hash->setKey('abcdefg');
 *
 *    echo base64_encode($hash->hash('abcdefg'));
 * ?>
 * </code>
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
 * @package    Crypt_Hash
 * @author     Jim Wigginton <terrafrost@php.net>
 * @copyright  MMVII Jim Wigginton
 * @license    http://www.gnu.org/licenses/lgpl.txt
 * @version    $Id: Hash.php,v 1.1 2009-02-16 22:22:13 terrafrost Exp $
 * @link       http://phpseclib.sourceforge.net
 */

/**#@+
 * @access private
 * @see Crypt_Hash::Crypt_Hash()
 */
/**
 * Toggles the internal implementation
 */
define('CRYPT_HASH_MODE_INTERNAL', 1);
/**
 * Toggles the mhash() implementation, which has been deprecated on PHP 5.3.0+.
 */
define('CRYPT_HASH_MODE_MHASH',    2);
/**
 * Toggles the hash() implementation, which works on PHP 5.1.2+.
 */
define('CRYPT_HASH_MODE_HASH',     3);
/**#@-*/

/**
 * Pure-PHP implementations of keyed-hash message authentication codes (HMACs) and various cryptographic hashing functions.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @version 0.1.0
 * @access  public
 * @package Crypt_Hash
 */
class Crypt_Hash {
    /**
     * Byte-length of compression blocks / key (Internal HMAC)
     *
     * @see Crypt_Hash::setAlgorithm()
     * @var Integer
     * @access private
     */
    var $b;

    /**
     * Byte-length of hash output (Internal HMAC)
     *
     * @see Crypt_Hash::setHash()
     * @var Integer
     * @access private
     */
    var $l;

    /**
     * Hash Algorithm
     *
     * @see Crypt_Hash::setHash()
     * @var String
     * @access private
     */
    var $hash;

    /**
     * Key
     *
     * @see Crypt_Hash::setKey()
     * @var String
     * @access private
     */
    var $key = '';

    /**
     * Outer XOR (Internal HMAC)
     *
     * @see Crypt_Hash::setKey()
     * @var String
     * @access private
     */
    var $opad;

    /**
     * Inner XOR (Internal HMAC)
     *
     * @see Crypt_Hash::setKey()
     * @var String
     * @access private
     */
    var $ipad;

    /**
     * Default Constructor.
     *
     * @param optional String $hash
     * @return Crypt_Hash
     * @access public
     */
    function Crypt_Hash($hash = 'sha1')
    {
        if ( !defined('CRYPT_HASH_MODE') ) {
            switch (true) {
                case extension_loaded('hash'):
                    define('CRYPT_HASH_MODE', CRYPT_HASH_MODE_HASH);
                    break;
                case extension_loaded('mhash'):
                    define('CRYPT_HASH_MODE', CRYPT_HASH_MODE_MHASH);
                    break;
                default:
                    define('CRYPT_HASH_MODE', CRYPT_HASH_MODE_INTERNAL);
            }
        }

        $this->setHash($hash);
    }

    /**
     * Sets the key for HMACs
     *
     * Keys can be of any length.
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
     * @access public
     * @param String $hash
     */
    function setHash($hash)
    {
        switch ($hash) {
            case 'md5-96':
            case 'sha1-96':
                $this->l = 12; // 96 / 8 = 12
                break;
            case 'md5':
                $this->l = 16;
                break;
            case 'sha1':
                $this->l = 20;
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
                 $this->hash = 'md5';
                 break;
            case 'sha1':
            case 'sha1-96':
            default:
                 $this->b = 64;
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
    function hash($text)
    {
        if (!empty($this->key)) {
            switch (CRYPT_HASH_MODE) {
                case CRYPT_HASH_MODE_MHASH:
                    $output = mhash($this->hash, $text, $this->key);
                    break;
                case CRYPT_HASH_MODE_HASH:
                    $output = hash_hmac($this->hash, $text, $this->key, true);
                    break;
                case CRYPT_HASH_MODE_INTERNAL:
                    $hash = $this->hash;
                    /* "Applications that use keys longer than B bytes will first hash the key using H and then use the
                        resultant L byte string as the actual key to HMAC."

                        -- http://tools.ietf.org/html/rfc2104#section-2 */
                    $key = strlen($this->key) > $this->b ? $hash($this->key) : $this->key;

                    $key    = str_pad($key, $this->b, chr(0));// step 1
                    $temp   = $this->ipad ^ $key;             // step 2
                    $temp  .= $text;                          // step 3
                    $temp   = pack('H*', $hash($temp));       // step 4
                    $output = $this->opad ^ $key;             // step 5
                    $output.= $temp;                          // step 6
                    $output = pack('H*', $hash($output));     // step 7
            }
        } else {
            switch (CRYPT_HASH_MODE) {
                case CRYPT_HASH_MODE_MHASH:
                    $output = mhash($this->hash, $text);
                    break;
                case CRYPT_HASH_MODE_MHASH:
                    $output = hash($this->hash, $text, true);
                    break;
                case CRYPT_HASH_MODE_INTERNAL:
                    $hash = $this->hash;
                    $output = pack('H*', $hash($output));
            }
        }

        return substr($output, 0, $this->l);
    }
}