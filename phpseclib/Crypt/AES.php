<?php

/**
 * Pure-PHP implementation of AES.
 *
 * Uses mcrypt, if available/possible, and an internal implementation, otherwise.
 *
 * PHP version 5
 *
 * NOTE: Since AES.php is (for compatibility and phpseclib-historical reasons) virtually
 * just a wrapper to Rijndael.php you may consider using Rijndael.php instead of
 * to save one include_once().
 *
 * If {@link self::setKeyLength() setKeyLength()} isn't called, it'll be calculated from
 * {@link self::setKey() setKey()}.  ie. if the key is 128-bits, the key length will be 128-bits.  If it's 136-bits
 * it'll be null-padded to 192-bits and 192 bits will be the key length until {@link self::setKey() setKey()}
 * is called, again, at which point, it'll be recalculated.
 *
 * Since \phpseclib\Crypt\AES extends \phpseclib\Crypt\Rijndael, some functions are available to be called that, in the context of AES, don't
 * make a whole lot of sense.  {@link self::setBlockLength() setBlockLength()}, for instance.  Calling that function,
 * however possible, won't do anything (AES has a fixed block length whereas Rijndael has a variable one).
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $aes = new \phpseclib\Crypt\AES();
 *
 *    $aes->setKey('abcdefghijklmnop');
 *
 *    $size = 10 * 1024;
 *    $plaintext = '';
 *    for ($i = 0; $i < $size; $i++) {
 *        $plaintext.= 'a';
 *    }
 *
 *    echo $aes->decrypt($aes->encrypt($plaintext));
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   AES
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2008 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt;

use phpseclib\Common\Functions\Strings;

/**
 * Pure-PHP implementation of AES.
 *
 * @package AES
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class AES extends Rijndael
{
    /**
     * Test for engine validity
     *
     * This is mainly just a wrapper to set things up for \phpseclib\Crypt\Common\SymmetricKey::isValidEngine()
     *
     * @see \phpseclib\Crypt\Common\SymmetricKey::__construct()
     * @param int $engine
     * @access protected
     * @return bool
     */
    protected function isValidEngineHelper($engine)
    {
        switch ($engine) {
            case self::ENGINE_LIBSODIUM:
                return function_exists('sodium_crypto_aead_aes256gcm_is_available') &&
                       sodium_crypto_aead_aes256gcm_is_available() &&
                       $this->mode == self::MODE_GCM &&
                       $this->key_length == 32 &&
                       $this->nonce && strlen($this->nonce) == 12;
            case self::ENGINE_OPENSSL_GCM:
                if (!extension_loaded('openssl')) {
                    return false;
                }
                $methods = openssl_get_cipher_methods();
                return $this->mode == self::MODE_GCM &&
                       version_compare(PHP_VERSION, '7.1.0', '>=') &&
                       in_array('aes-' . $this->getKeyLength() . '-gcm', $methods);
        }

        return parent::isValidEngineHelper($engine);
    }

    /**
     * Dummy function
     *
     * Since \phpseclib\Crypt\AES extends \phpseclib\Crypt\Rijndael, this function is, technically, available, but it doesn't do anything.
     *
     * @see \phpseclib\Crypt\Rijndael::setBlockLength()
     * @access public
     * @param int $length
     * @throws \BadMethodCallException anytime it's called
     */
    public function setBlockLength($length)
    {
        throw new \BadMethodCallException('The block length cannot be set for AES.');
    }

    /**
     * Sets the key length
     *
     * Valid key lengths are 128, 192, and 256.  Set the link to bool(false) to disable a fixed key length
     *
     * @see \phpseclib\Crypt\Rijndael:setKeyLength()
     * @access public
     * @param int $length
     * @throws \LengthException if the key length isn't supported
     */
    public function setKeyLength($length)
    {
        switch ($length) {
            case 128:
            case 192:
            case 256:
                break;
            default:
                throw new \LengthException('Key of size ' . $length . ' not supported by this algorithm. Only keys of sizes 128, 192 or 256 supported');
        }
        parent::setKeyLength($length);
    }

    /**
     * Sets the key.
     *
     * Rijndael supports five different key lengths, AES only supports three.
     *
     * @see \phpseclib\Crypt\Rijndael:setKey()
     * @see setKeyLength()
     * @access public
     * @param string $key
     * @throws \LengthException if the key length isn't supported
     */
    public function setKey($key)
    {
        switch (strlen($key)) {
            case 16:
            case 24:
            case 32:
                break;
            default:
                throw new \LengthException('Key of size ' . strlen($key) . ' not supported by this algorithm. Only keys of sizes 16, 24 or 32 supported');
        }

        parent::setKey($key);
    }

    /**
     * Encrypts a message.
     *
     * @see self::decrypt()
     * @see parent::encrypt()
     * @access public
     * @param string $plaintext
     * @return string
     */
    public function encrypt($plaintext)
    {
        switch ($this->engine) {
            case self::ENGINE_LIBSODIUM:
                $this->checkForChanges();
                $this->newtag = sodium_crypto_aead_aes256gcm_encrypt($plaintext, $this->aad, $this->nonce, $this->key);
                return Strings::shift($this->newtag, strlen($plaintext));
            case self::ENGINE_OPENSSL_GCM:
                $this->checkForChanges();
                return openssl_encrypt(
                    $plaintext,
                    'aes-' . $this->getKeyLength() . '-gcm',
                    $this->key,
                    OPENSSL_RAW_DATA,
                    $this->nonce,
                    $this->newtag,
                    $this->aad
                );
        }

        return parent::encrypt($plaintext);
    }

    /**
     * Decrypts a message.
     *
     * @see self::encrypt()
     * @see parent::decrypt()
     * @access public
     * @param string $ciphertext
     * @return string
     */
    public function decrypt($ciphertext)
    {
        switch ($this->engine) {
            case self::ENGINE_LIBSODIUM:
                $this->checkForChanges();
                if ($this->oldtag === false) {
                    throw new \UnexpectedValueException('Authentication Tag has not been set');
                }
                if (strlen($this->oldtag) != 16) {
                    break;
                }
                $plaintext = sodium_crypto_aead_aes256gcm_decrypt($ciphertext . $this->oldtag, $this->aad, $this->nonce, $this->key);
                if ($plaintext === false) {
                    $this->oldtag = false;
                    throw new \UnexpectedValueException('Error decrypting ciphertext with libsodium');
                }
                return $plaintext;
            case self::ENGINE_OPENSSL_GCM:
                $this->checkForChanges();
                if ($this->oldtag === false) {
                    throw new \UnexpectedValueException('Authentication Tag has not been set');
                }
                $plaintext = openssl_decrypt(
                    $ciphertext,
                    'aes-' . $this->getKeyLength() . '-gcm',
                    $this->key,
                    OPENSSL_RAW_DATA,
                    $this->nonce,
                    $this->oldtag,
                    $this->aad
                );
                if ($plaintext === false) {
                    $this->oldtag = false;
                    throw new \UnexpectedValueException('Error decrypting ciphertext with OpenSSL');
                }
                return $plaintext;
        }

        return parent::decrypt($ciphertext);
    }

    /**
     * Check For Changes
     *
     * @see self::encrypt()
     * @see self::decrypt()
     * @access private
     */
    private function checkForChanges()
    {
        if ($this->changed) {
            $this->clearBuffers();
            $this->changed = false;
        }
    }
}
