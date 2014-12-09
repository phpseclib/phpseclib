<?php

/**
 * Pure-PHP implementation of RC4.
 *
 * Uses mcrypt, if available, and an internal implementation, otherwise.
 *
 * PHP versions 4 and 5
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
 *    include 'Crypt/RC4.php';
 *
 *    $rc4 = new Crypt_RC4();
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
 * @package   Crypt_RC4
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright MMVII Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

/**
 * Include Crypt_Base
 *
 * Base cipher class
 */
if (!class_exists('Crypt_Base')) {
    include_once 'Base.php';
}

/**
 * Pure-PHP implementation of RC4.
 *
 * @package Crypt_RC4
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class Crypt_RC4 extends Crypt_Base
{
    /**#@+
     * @access private
     * @see Crypt_RC4::_crypt()
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
     * @see Crypt_Base::block_size
     * @var Integer
     * @access private
     */
    var $block_size = 0;

    /**
     * The default password key_size used by setPassword()
     *
     * @see Crypt_Base::password_key_size
     * @see Crypt_Base::setPassword()
     * @var Integer
     * @access private
     */
    var $password_key_size = 128; // = 1024 bits

    /**
     * The mcrypt specific name of the cipher
     *
     * @see Crypt_Base::cipher_name_mcrypt
     * @var String
     * @access private
     */
    var $cipher_name_mcrypt = 'arcfour';

    /**
     * Holds whether performance-optimized $inline_crypt() can/should be used.
     *
     * @see Crypt_Base::inline_crypt
     * @var mixed
     * @access private
     */
    var $use_inline_crypt = false; // currently not available

    /**
     * The Key
     *
     * @see Crypt_RC4::setKey()
     * @var String
     * @access private
     */
    var $key = "\0";

    /**
     * The Key Stream for decryption and encryption
     *
     * @see Crypt_RC4::setKey()
     * @var Array
     * @access private
     */
    var $stream;

    /**
     * Default Constructor.
     *
     * Determines whether or not the mcrypt extension should be used.
     *
     * @see Crypt_Base::__construct()
     * @return Crypt_RC4
     * @access public
     */
    function __construct()
    {
        parent::__construct(Crypt_Base::MODE_STREAM);
    }

    /**
     * Dummy function.
     *
     * Some protocols, such as WEP, prepend an "initialization vector" to the key, effectively creating a new key [1].
     * If you need to use an initialization vector in this manner, feel free to prepend it to the key, yourself, before
     * calling setKey().
     *
     * [1] WEP's initialization vectors (IV's) are used in a somewhat insecure way.  Since, in that protocol,
     * the IV's are relatively easy to predict, an attack described by
     * {@link http://www.drizzle.com/~aboba/IEEE/rc4_ksaproc.pdf Scott Fluhrer, Itsik Mantin, and Adi Shamir}
     * can be used to quickly guess at the rest of the key.  The following links elaborate:
     *
     * {@link http://www.rsa.com/rsalabs/node.asp?id=2009 http://www.rsa.com/rsalabs/node.asp?id=2009}
     * {@link http://en.wikipedia.org/wiki/Related_key_attack http://en.wikipedia.org/wiki/Related_key_attack}
     *
     * @param String $iv
     * @see Crypt_RC4::setKey()
     * @access public
     */
    function setIV($iv)
    {
    }

    /**
     * Sets the key.
     *
     * Keys can be between 1 and 256 bytes long.  If they are longer then 256 bytes, the first 256 bytes will
     * be used.  If no key is explicitly set, it'll be assumed to be a single null byte.
     *
     * @access public
     * @see Crypt_Base::setKey()
     * @param String $key
     */
    function setKey($key)
    {
        parent::setKey(substr($key, 0, 256));
    }

    /**
     * Encrypts a message.
     *
     * @see Crypt_Base::decrypt()
     * @see Crypt_RC4::_crypt()
     * @access public
     * @param String $plaintext
     * @return String $ciphertext
     */
    function encrypt($plaintext)
    {
        if ($this->engine == Crypt_Base::ENGINE_MCRYPT) {
            return parent::encrypt($plaintext);
        }
        return $this->_crypt($plaintext, self::ENCRYPT);
    }

    /**
     * Decrypts a message.
     *
     * $this->decrypt($this->encrypt($plaintext)) == $this->encrypt($this->encrypt($plaintext)).
     * At least if the continuous buffer is disabled.
     *
     * @see Crypt_Base::encrypt()
     * @see Crypt_RC4::_crypt()
     * @access public
     * @param String $ciphertext
     * @return String $plaintext
     */
    function decrypt($ciphertext)
    {
        if ($this->engine == Crypt_Base::ENGINE_MCRYPT) {
            return parent::decrypt($ciphertext);
        }
        return $this->_crypt($ciphertext, self::DECRYPT);
    }


    /**
     * Setup the key (expansion)
     *
     * @see Crypt_Base::_setupKey()
     * @access private
     */
    function _setupKey()
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

        $this->stream = array();
        $this->stream[self::DECRYPT] = $this->stream[self::ENCRYPT] = array(
            0, // index $i
            0, // index $j
            $keyStream
        );
    }

    /**
     * Encrypts or decrypts a message.
     *
     * @see Crypt_RC4::encrypt()
     * @see Crypt_RC4::decrypt()
     * @access private
     * @param String $text
     * @param Integer $mode
     * @return String $text
     */
    function _crypt($text, $mode)
    {
        if ($this->changed) {
            $this->_setup();
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
