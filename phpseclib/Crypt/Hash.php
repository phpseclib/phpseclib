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

use phpseclib\Exception\UnsupportedAlgorithmException;

/**
 * @package Hash
 * @author  Jim Wigginton <terrafrost@php.net>
 * @author  Andreas Fischer <bantu@phpbb.com>
 * @access  public
 */
class Hash
{
    /**
     * Hash Parameter
     *
     * @see self::setHash()
     * @var int
     * @access private
     */
    var $hashParam;

    /**
     * Byte-length of hash output (Internal HMAC)
     *
     * @see self::setHash()
     * @var int
     * @access private
     */
    var $length;

    /**
     * Bit-length of hash BlockSize (Internal HMAC)
     *
     * @see self::setHash()
     * @var int
     * @access private
     */
    var $BlockSize;
    
    /**
     * Hash Algorithm
     *
     * @see self::setHash()
     * @var string
     * @access private
     */
    var $hash;

    /**
     * Key
     *
     * @see self::setKey()
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
        if ($key < $this->length) 
        {
            throw new Exception ("Key is too short, it must be at least {$this->length}.");
        } 
        elseif ($key > $this->getBlockSize())
        {
               $key = substr($key, 0, $this->getBlockSize());
        }
        
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
                $this->BlockSize = 512;
                $hash = substr($hash, 0, -3);
                $this->length = 12; // 96 / 8 = 12
                break;
            case 'sha512-96':
                $this->BlockSize = 1024;
                $hash = substr($hash, 0, -3);
                $this->length = 12; // 96 / 8 = 12
                break;
            case 'md2':
                $this->BlockSize = 128;
                $this->length = 16;
                break;
            case 'md5':
                $this->BlockSize = 512;
                $this->length = 16;
                break;
            case 'sha1':
                $this->BlockSize = 512;
                $this->length = 20;
                break;
            case 'sha256':
                $this->BlockSize = 512;
                $this->length = 32;
                break;
            case 'sha384':
                $this->BlockSize = 1024;
                $this->length = 48;
                break;
            case 'sha512':
                $this->BlockSize = 1024;
                $this->length = 64;
                break;
            default:
                // see if the hash isn't "officially" supported see if it can
                // be "unofficially" supported and calculate the length
                // accordingly.
                if (in_array($hash, hash_algos())) {
                    $this->length = strlen(hash($hash, '', true));
                    break;
                }
                // if the hash algorithm doens't exist maybe it's a truncated
                // hash, e.g. whirlpool-12 or some such.
                if (preg_match('#(-\d+)$#', $hash, $matches)) {
                    $hash = substr($hash, 0, -strlen($matches[1]));
                    if (in_array($hash, hash_algos())) {
                        $this->length = abs($matches[1]) >> 3;
                        break;
                    }
                }
                throw new UnsupportedAlgorithmException(
                    "$hash is not a supported algorithm"
                );
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

        return strlen($output) > $this->length
            ? substr($output, 0, $this->length)
            : $output;
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
    
    /**
     * Returns the hash BlockSize (in bits)
     *
     * @access public
     * @return int
     */
    function getBlockSizeInBits()
    {
        return $this->BlockSize;
    }
    
    /**
     * Returns the hash BlockSize (in bytes)
     *
     * @access public
     * @return int
     */
    function getBlockSize()
    {
        return $this->getBlockSizeInBits() / 8;
    }
    
}
