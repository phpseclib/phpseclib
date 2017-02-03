<?php

/**
 * Pure-PHP implementation of RC4.
 *
 * Uses mcrypt, if available, and an internal implementation, otherwise.
 *
 * PHP version 5
 *
 * Useful resources are as follows:
 *
 *  - {@link http://www.mozilla.org/projects/security/pki/nss/draft-kaukonen-cipher-arcfour-03.txt ARCFOUR Algorithm}
 *  - {@link http://en.wikipedia.org/wiki/RC4 - Wikipedia: RC4}
 *
 * RC4 is also known as ARCFOUR or ARC4.  The reason is elaborated upon at Wikipedia.  This class is named RC4 and not
 * ARCFOUR or ARC4 because RC4 is how it is referred to in the SSH1 specification.
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $rc4 = new \phpseclib\Crypt\RC4();
 *
 *    $rc4->setKey('abcdefgh');
 *
 *    $size = 10 * 1024;
 *    $plaintext = '';
 *    for ($i = 0; $i < $size; $i++) {
 *        $plaintext.= 'a';
 *    }
 *
 *    echo $rc4->decrypt($rc4->encrypt($plaintext));
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   RC4
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt;

use phpseclib\Crypt\Common\StreamCipher;

/**
 * Pure-PHP implementation of RC4.
 *
 * @package RC4
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class RC4 extends StreamCipher
{
    /**#@+
     * @access private
     * @see \phpseclib\Crypt\RC4::_crypt()
    */
    const ENCRYPT = 0;
    const DECRYPT = 1;
    /**#@-*/

    /**
     * Block Length of the cipher
     *
     * RC4 is a stream cipher
     * so we the block_size to 0
     *
     * @see \phpseclib\Crypt\Common\SymmetricKey::block_size
     * @var int
     * @access private
     */
    protected $block_size = 0;

    /**
     * Key Length (in bytes)
     *
     * @see \phpseclib\Crypt\RC4::setKeyLength()
     * @var int
     * @access private
     */
    protected $key_length = 128; // = 1024 bits

    /**
     * The mcrypt specific name of the cipher
     *
     * @see \phpseclib\Crypt\Common\SymmetricKey::cipher_name_mcrypt
     * @var string
     * @access private
     */
    protected $cipher_name_mcrypt = 'arcfour';

    /**
     * Holds whether performance-optimized $inline_crypt() can/should be used.
     *
     * @see \phpseclib\Crypt\Common\SymmetricKey::inline_crypt
     * @var mixed
     * @access private
     */
    protected $use_inline_crypt = false; // currently not available

    /**
     * The Key
     *
     * @see self::setKey()
     * @var string
     * @access private
     */
    protected $key;

    /**
     * The Key Stream for decryption and encryption
     *
     * @see self::setKey()
     * @var array
     * @access private
     */
    private $stream;

    /**
     * Default Constructor.
     *
     * @see \phpseclib\Crypt\Common\SymmetricKey::__construct()
     * @return \phpseclib\Crypt\RC4
     * @access public
     */
    public function __construct()
    {
        parent::__construct(self::MODE_STREAM);
    }

    /**
     * Test for engine validity
     *
     * This is mainly just a wrapper to set things up for \phpseclib\Crypt\Common\SymmetricKey::isValidEngine()
     *
     * @see \phpseclib\Crypt\Common\SymmetricKey::__construct()
     * @param int $engine
     * @access public
     * @return bool
     */
    public function isValidEngine($engine)
    {
        if ($engine == self::ENGINE_OPENSSL) {
            $this->cipher_name_openssl = 'rc4-40';
        }

        return parent::isValidEngine($engine);
    }

    /**
     * RC4 does not use an IV
     *
     * @access public
     * @return bool
     */
    public function usesIV()
    {
        return false;
    }

    /**
     * Sets the key length
     *
     * Keys can be between 1 and 256 bytes long.
     *
     * @access public
     * @param int $length
     * @throws \LengthException if the key length is invalid
     */
    public function setKeyLength($length)
    {
        if ($length < 8 || $length > 2048) {
            throw new \LengthException('Key size of ' . $length . ' bits is not supported by this algorithm. Only keys between 1 and 256 bytes are supported');
        }

        $this->key_length = $length >> 3;

        parent::setKeyLength($length);
    }

    /**
     * Sets the key length
     *
     * Keys can be between 1 and 256 bytes long.
     *
     * @access public
     * @param int $length
     * @throws \LengthException if the key length is invalid
     */
    public function setKey($key)
    {
        $length = strlen($key);
        if ($length < 1 || $length > 256) {
            throw new \LengthException('Key size of ' . $length . ' bytes is not supported by RC4. Keys must be between 1 and 256 bytes long');
        }

        parent::setKey($key);
    }

    /**
     * Encrypts a message.
     *
     * @see \phpseclib\Crypt\Common\SymmetricKey::decrypt()
     * @see self::crypt()
     * @access public
     * @param string $plaintext
     * @return string $ciphertext
     */
    public function encrypt($plaintext)
    {
        if ($this->engine != self::ENGINE_INTERNAL) {
            return parent::encrypt($plaintext);
        }
        return $this->crypt($plaintext, self::ENCRYPT);
    }

    /**
     * Decrypts a message.
     *
     * $this->decrypt($this->encrypt($plaintext)) == $this->encrypt($this->encrypt($plaintext)).
     * At least if the continuous buffer is disabled.
     *
     * @see \phpseclib\Crypt\Common\SymmetricKey::encrypt()
     * @see self::crypt()
     * @access public
     * @param string $ciphertext
     * @return string $plaintext
     */
    public function decrypt($ciphertext)
    {
        if ($this->engine != self::ENGINE_INTERNAL) {
            return parent::decrypt($ciphertext);
        }
        return $this->crypt($ciphertext, self::DECRYPT);
    }

    /**
     * Encrypts a block
     *
     * @access private
     * @param string $in
     */
    protected function encryptBlock($in)
    {
        // RC4 does not utilize this method
    }

    /**
     * Decrypts a block
     *
     * @access private
     * @param string $in
     */
    protected function decryptBlock($in)
    {
        // RC4 does not utilize this method
    }

    /**
     * Setup the key (expansion)
     *
     * @see \phpseclib\Crypt\Common\SymmetricKey::_setupKey()
     * @access private
     */
    protected function setupKey()
    {
        $key = $this->key;
        $keyLength = strlen($key);
        $keyStream = range(0, 255);
        $j = 0;
        for ($i = 0; $i < 256; $i++) {
            $j = ($j + $keyStream[$i] + ord($key[$i % $keyLength])) & 255;
            $temp = $keyStream[$i];
            $keyStream[$i] = $keyStream[$j];
            $keyStream[$j] = $temp;
        }

        $this->stream = [];
        $this->stream[self::DECRYPT] = $this->stream[self::ENCRYPT] = [
            0, // index $i
            0, // index $j
            $keyStream
        ];
    }

    /**
     * Encrypts or decrypts a message.
     *
     * @see self::encrypt()
     * @see self::decrypt()
     * @access private
     * @param string $text
     * @param int $mode
     * @return string $text
     */
    private function crypt($text, $mode)
    {
        if ($this->changed) {
            $this->setup();
            $this->changed = false;
        }

        $stream = &$this->stream[$mode];
        if ($this->continuousBuffer) {
            $i = &$stream[0];
            $j = &$stream[1];
            $keyStream = &$stream[2];
        } else {
            $i = $stream[0];
            $j = $stream[1];
            $keyStream = $stream[2];
        }

        $len = strlen($text);
        for ($k = 0; $k < $len; ++$k) {
            $i = ($i + 1) & 255;
            $ksi = $keyStream[$i];
            $j = ($j + $ksi) & 255;
            $ksj = $keyStream[$j];

            $keyStream[$i] = $ksj;
            $keyStream[$j] = $ksi;
            $text[$k] = $text[$k] ^ chr($keyStream[($ksj + $ksi) & 255]);
        }

        return $text;
    }
}
