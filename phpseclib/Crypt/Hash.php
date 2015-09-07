<?php

/**
 * Pure-PHP implementations of keyed-hash message authentication codes (HMACs) and various cryptographic hashing functions.
 *
 * Basically a wrapper for hash().  Currently supports the following:
 *
 * md2, md5, md5-96, sha1, sha1-96, sha256, sha256-96, sha384, and sha512, sha512-96
 *
 * If {@link \phpseclib\Crypt\Hash::setKey() setKey()} is called, {@link \phpseclib\Crypt\Hash::hash() hash()} will return the HMAC as opposed to
 * the hash.  If no valid algorithm is provided, sha1 will be used.
 *
 * PHP version 5
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $hash = new \phpseclib\Crypt\Hash('sha1');
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
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt;

use phpseclib\Exception\UnsupportedAlgorithmException;

/**
 * Pure-PHP implementations of keyed-hash message authentication codes (HMACs) and various cryptographic hashing functions.
 *
 * @package Hash
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class Hash
{
    /**
     * Hash Parameter
     *
     * @see \phpseclib\Crypt\Hash::setHash()
     * @var int
     * @access private
     */
    var $hashParam;

    /**
     * Byte-length of hash output (Internal HMAC)
     *
     * @see \phpseclib\Crypt\Hash::setHash()
     * @var int
     * @access private
     */
    var $length;

    /**
     * Hash Algorithm
     *
     * @see \phpseclib\Crypt\Hash::setHash()
     * @var string
     * @access private
     */
    var $hash;

    /**
     * Key
     *
     * @see \phpseclib\Crypt\Hash::setKey()
     * @var string
     * @access private
     */
    var $key = false;

    /**
     * Default Constructor.
     *
     * @param string $hash
     * @access public
     */
    function __construct($hash = 'sha256')
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
            case 'md5-96':
            case 'sha1-96':
            case 'sha256-96':
            case 'sha512-96':
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
            case 'sha256':
                $this->length = 32;
                break;
            case 'sha384':
                $this->length = 48;
                break;
            case 'sha512':
                $this->length = 64;
                break;
            default:
                // see if the hash isn't "officially" supported see if it can be "unofficially" supported and calculate the length accordingly
                if (in_array($hash, hash_algos())) {
                    $this->length = strlen(hash($hash, '', true));
                    break;
                }
                // if the hash algorithm doens't exist maybe it's a truncated hash. eg. md5-96 or some such
                if (preg_match('#(-\d+)$#', $hash, $matches) && in_array($hash = substr($hash, 0, -strlen($matches[1])), hash_algos())) {
                    $this->length = abs($matches[1]) >> 3;
                    break;
                }
                throw new UnsupportedAlgorithmException("$hash is not a supported algorithm");
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
        $output = !empty($this->key) || is_string($this->key) ?
            hash_hmac($this->hash, $text, $this->key, true) :
            hash($this->hash, $text, true);

        return strlen($output) > $this->length ? substr($output, 0, $this->length) : $output;
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
}
