<?php

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
        switch (CRYPT_HMAC_MODE) {
            case CRYPT_HMAC_MODE_MHASH:
                switch ($hash) {
                    case 'md5':
                        $this->hash = MHASH_MD5;
                        break;
                    case 'sha1':
                    default:
                        $this->hash = MHASH_SHA1;
                }
                return;
            case CRYPT_HMAC_MODE_HASH:
                switch ($hash) {
                    case 'md5':
                    case 'sha1':
                        $this->hash = $hash;
                        return;
                    default:
                        $this->hash = 'sha1';
                }
        }

        switch ($hash) {
            case 'md5':
                 $this->b = 64;
                 $this->l = 16;
                 $this->hash = 'md5';
                 break;
            case 'sha1':
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
                return mhash($this->hash, $text, $this->key);
            case CRYPT_HMAC_MODE_HASH:
                return hash_hmac($this->hash, $text, $this->key, true);
        }

        $hash = $this->hash;

        $key = strlen($this->key) > $this->b ? $this->hash($this->key) : $this->key;
        $key = str_pad($key, $this->b, chr(0)); // step 1
        $temp = $this->ipad ^ $key;             // step 2
        $temp.= $text;                          // step 3
        $temp = pack('H*', $hash($temp));       // step 4
        $hmac = $this->opad ^ $key;             // step 5
        $hmac.= $temp;                          // step 6
        $hmac = pack('H*', $hash($hmac));       // step 7

        return $hmac;
    }
}