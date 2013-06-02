<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Pure-PHP implementation of Triple DES.
 *
 * Uses mcrypt, if available, and an internal implementation, otherwise.  Operates in the EDE3 mode (encrypt-decrypt-encrypt).
 *
 * PHP versions 4 and 5
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include('Crypt/TripleDES.php');
 *
 *    $des = new Crypt_TripleDES();
 *
 *    $des->setKey('abcdefghijklmnopqrstuvwx');
 *
 *    $size = 10 * 1024;
 *    $plaintext = '';
 *    for ($i = 0; $i < $size; $i++) {
 *        $plaintext.= 'a';
 *    }
 *
 *    echo $des->decrypt($des->encrypt($plaintext));
 * ?>
 * </code>
 *
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @category   Crypt
 * @package    Crypt_TripleDES
 * @author     Jim Wigginton <terrafrost@php.net>
 * @copyright  MMVII Jim Wigginton
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       http://phpseclib.sourceforge.net
 */

/**
 * Include Crypt_DES
 */
if (!class_exists('Crypt_DES')) {
    require_once('DES.php');
}

/**
 * Encrypt / decrypt using inner chaining
 *
 * Inner chaining is used by SSH-1 and is generally considered to be less secure then outer chaining (CRYPT_DES_MODE_CBC3).
 */
define('CRYPT_DES_MODE_3CBC', -2);

/**
 * Encrypt / decrypt using outer chaining
 *
 * Outer chaining is used by SSH-2 and when the mode is set to CRYPT_DES_MODE_CBC.
 */
define('CRYPT_DES_MODE_CBC3', CRYPT_DES_MODE_CBC);

/**
 * Pure-PHP implementation of Triple DES.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @version 0.1.0
 * @access  public
 * @package Crypt_TerraDES
 */
class Crypt_TripleDES extends Crypt_DES {
    /**
     * The Crypt_DES objects
     *
     * @var Array
     * @access private
     */
    var $des;

    /**
     * Default Constructor.
     *
     * Determines whether or not the mcrypt extension should be used.  $mode should only, at present, be
     * CRYPT_DES_MODE_ECB or CRYPT_DES_MODE_CBC.  If not explictly set, CRYPT_DES_MODE_CBC will be used.
     *
     * @param optional Integer $mode
     * @return Crypt_TripleDES
     * @access public
     */
    function Crypt_TripleDES($mode = CRYPT_DES_MODE_CBC)
    {
        if ( !defined('CRYPT_DES_MODE') ) {
            switch (true) {
                case extension_loaded('mcrypt') && in_array('tripledes', mcrypt_list_algorithms()):
                    define('CRYPT_DES_MODE', CRYPT_DES_MODE_MCRYPT);
                    break;
                default:
                    define('CRYPT_DES_MODE', CRYPT_DES_MODE_INTERNAL);
            }
        }

        if ( $mode == CRYPT_DES_MODE_3CBC ) {
            $this->mode = CRYPT_DES_MODE_3CBC;
            $this->des = array(
                new Crypt_DES(CRYPT_DES_MODE_CBC),
                new Crypt_DES(CRYPT_DES_MODE_CBC),
                new Crypt_DES(CRYPT_DES_MODE_CBC)
            );
            $this->paddable = true;

            // we're going to be doing the padding, ourselves, so disable it in the Crypt_DES objects
            $this->des[0]->disablePadding();
            $this->des[1]->disablePadding();
            $this->des[2]->disablePadding();

            return;
        }

        switch ( CRYPT_DES_MODE ) {
            case CRYPT_DES_MODE_MCRYPT:
                switch ($mode) {
                    case CRYPT_DES_MODE_ECB:
                        $this->paddable = true;
                        $this->mode = MCRYPT_MODE_ECB;
                        break;
                    case CRYPT_DES_MODE_CTR:
                        $this->mode = 'ctr';
                        break;
                    case CRYPT_DES_MODE_CFB:
                        $this->mode = 'ncfb';
                        $this->ecb = mcrypt_module_open(MCRYPT_3DES, '', MCRYPT_MODE_ECB, '');
                        break;
                    case CRYPT_DES_MODE_OFB:
                        $this->mode = MCRYPT_MODE_NOFB;
                        break;
                    case CRYPT_DES_MODE_CBC:
                    default:
                        $this->paddable = true;
                        $this->mode = MCRYPT_MODE_CBC;
                }
                $this->enmcrypt = mcrypt_module_open(MCRYPT_3DES, '', $this->mode, '');
                $this->demcrypt = mcrypt_module_open(MCRYPT_3DES, '', $this->mode, '');

                break;
            default:
                $this->des = array(
                    new Crypt_DES(CRYPT_DES_MODE_ECB),
                    new Crypt_DES(CRYPT_DES_MODE_ECB),
                    new Crypt_DES(CRYPT_DES_MODE_ECB)
                );
 
                // we're going to be doing the padding, ourselves, so disable it in the Crypt_DES objects
                $this->des[0]->disablePadding();
                $this->des[1]->disablePadding();
                $this->des[2]->disablePadding();

                switch ($mode) {
                    case CRYPT_DES_MODE_ECB:
                    case CRYPT_DES_MODE_CBC:
                        $this->paddable = true;
                        $this->mode = $mode;
                        break;
                    case CRYPT_DES_MODE_CTR:
                    case CRYPT_DES_MODE_CFB:
                    case CRYPT_DES_MODE_OFB:
                        $this->mode = $mode;
                        break;
                    default:
                        $this->paddable = true;
                        $this->mode = CRYPT_DES_MODE_CBC;
                }
                if (function_exists('create_function') && is_callable('create_function')) {
                    $this->inline_crypt_setup(3);
                    $this->use_inline_crypt = true;
                }
        }
    }

    /**
     * Sets the key.
     *
     * Keys can be of any length.  Triple DES, itself, can use 128-bit (eg. strlen($key) == 16) or
     * 192-bit (eg. strlen($key) == 24) keys.  This function pads and truncates $key as appropriate.
     *
     * DES also requires that every eighth bit be a parity bit, however, we'll ignore that.
     *
     * If the key is not explicitly set, it'll be assumed to be all zero's.
     *
     * @access public
     * @param String $key
     */
    function setKey($key)
    {
        $length = strlen($key);
        if ($length > 8) {
            $key = str_pad($key, 24, chr(0));
            // if $key is between 64 and 128-bits, use the first 64-bits as the last, per this:
            // http://php.net/function.mcrypt-encrypt#47973
            //$key = $length <= 16 ? substr_replace($key, substr($key, 0, 8), 16) : substr($key, 0, 24);
        } else {
            $key = str_pad($key, 8, chr(0));
        }
        $this->key = $key;
        switch (true) {
            case CRYPT_DES_MODE == CRYPT_DES_MODE_INTERNAL:
            case $this->mode == CRYPT_DES_MODE_3CBC:
                $this->des[0]->setKey(substr($key,  0, 8));
                $this->des[1]->setKey(substr($key,  8, 8));
                $this->des[2]->setKey(substr($key, 16, 8));

                // Merge the three DES-1-dim-key-arrays for 3DES-inline-en/decrypting  
                if ($this->use_inline_crypt && $this->mode != CRYPT_DES_MODE_3CBC) {
                    $this->keys = array(
                        CRYPT_DES_ENCRYPT_1DIM => array_merge(
                            $this->des[0]->keys[CRYPT_DES_ENCRYPT_1DIM],
                            $this->des[1]->keys[CRYPT_DES_DECRYPT_1DIM],
                            $this->des[2]->keys[CRYPT_DES_ENCRYPT_1DIM]
                        ),
                        CRYPT_DES_DECRYPT_1DIM => array_merge(
                            $this->des[2]->keys[CRYPT_DES_DECRYPT_1DIM],
                            $this->des[1]->keys[CRYPT_DES_ENCRYPT_1DIM],
                            $this->des[0]->keys[CRYPT_DES_DECRYPT_1DIM]
                        ),
                    );
                }
        }
        $this->enchanged = $this->dechanged = true;
    }

    /**
     * Sets the password.
     *
     * Depending on what $method is set to, setPassword()'s (optional) parameters are as follows:
     *     {@link http://en.wikipedia.org/wiki/PBKDF2 pbkdf2}:
     *         $hash, $salt, $method
     *
     * @param String $password
     * @param optional String $method
     * @access public
     */
    function setPassword($password, $method = 'pbkdf2')
    {
        $key = '';

        switch ($method) {
            default: // 'pbkdf2'
                list(, , $hash, $salt, $count) = func_get_args();
                if (!isset($hash)) {
                    $hash = 'sha1';
                }
                // WPA and WPA2 use the SSID as the salt
                if (!isset($salt)) {
                    $salt = 'phpseclib';
                }
                // RFC2898#section-4.2 uses 1,000 iterations by default
                // WPA and WPA2 use 4,096.
                if (!isset($count)) {
                    $count = 1000;
                }

                if (!class_exists('Crypt_Hash')) {
                    require_once('Crypt/Hash.php');
                }

                $i = 1;
                while (strlen($key) < 24) { // $dkLen == 24
                    $hmac = new Crypt_Hash();
                    $hmac->setHash($hash);
                    $hmac->setKey($password);
                    $f = $u = $hmac->hash($salt . pack('N', $i++));
                    for ($j = 2; $j <= $count; $j++) {
                        $u = $hmac->hash($u);
                        $f^= $u;
                    }
                    $key.= $f;
                }
        }

        $this->setKey($key);
    }

    /**
     * Sets the initialization vector. (optional)
     *
     * SetIV is not required when CRYPT_DES_MODE_ECB is being used.  If not explictly set, it'll be assumed
     * to be all zero's.
     *
     * @access public
     * @param String $iv
     */
    function setIV($iv)
    {
        $this->encryptIV = $this->decryptIV = $this->iv = str_pad(substr($iv, 0, 8), 8, chr(0));
        if ($this->mode == CRYPT_DES_MODE_3CBC) {
            $this->des[0]->setIV($iv);
            $this->des[1]->setIV($iv);
            $this->des[2]->setIV($iv);
        }
        $this->enchanged = $this->dechanged = true;
    }

    /**
     * Encrypts a message.
     *
     * @access public
     * @param String $plaintext
     */
    function encrypt($plaintext)
    {
        if ($this->paddable) {
            $plaintext = $this->_pad($plaintext);
        }

        // if the key is smaller then 8, do what we'd normally do
        if ($this->mode == CRYPT_DES_MODE_3CBC && strlen($this->key) > 8) {
            $ciphertext = $this->des[2]->encrypt($this->des[1]->decrypt($this->des[0]->encrypt($plaintext)));

            return $ciphertext;
        }

        if ( CRYPT_DES_MODE == CRYPT_DES_MODE_MCRYPT ) {
            if ($this->enchanged) {
                mcrypt_generic_init($this->enmcrypt, $this->key, $this->encryptIV);
                if ($this->mode == 'ncfb') {
                    mcrypt_generic_init($this->ecb, $this->key, "\0\0\0\0\0\0\0\0");
                }
                $this->enchanged = false;
            }

            if ($this->mode != 'ncfb' || !$this->continuousBuffer) {
                $ciphertext = mcrypt_generic($this->enmcrypt, $plaintext);
            } else {
                $iv = &$this->encryptIV;
                $pos = &$this->enbuffer['pos'];
                $len = strlen($plaintext);
                $ciphertext = '';
                $i = 0;
                if ($pos) {
                    $orig_pos = $pos;
                    $max = 8 - $pos;
                    if ($len >= $max) {
                        $i = $max;
                        $len-= $max;
                        $pos = 0;
                    } else {
                        $i = $len;
                        $pos+= $len;
                        $len = 0;
                    }
                    $ciphertext = substr($iv, $orig_pos) ^ $plaintext;
                    $iv = substr_replace($iv, $ciphertext, $orig_pos, $i);
                    $this->enbuffer['enmcrypt_init'] = true;
                }
                if ($len >= 8) {
                    if ($this->enbuffer['enmcrypt_init'] === false || $len > 950) {
                        if ($this->enbuffer['enmcrypt_init'] === true) {
                            mcrypt_generic_init($this->enmcrypt, $this->key, $iv);
                            $this->enbuffer['enmcrypt_init'] = false;
                        }
                        $ciphertext.= mcrypt_generic($this->enmcrypt, substr($plaintext, $i, $len - $len % 8));
                        $iv = substr($ciphertext, -8);
                        $i = strlen($ciphertext);
                        $len%= 8;
                    } else {
                        while ($len >= 8) {
                            $iv = mcrypt_generic($this->ecb, $iv) ^ substr($plaintext, $i, 8);
                            $ciphertext.= $iv;
                            $len-= 8;
                            $i+= 8;
                        }
                    }
                } 
                if ($len) {
                    $iv = mcrypt_generic($this->ecb, $iv);
                    $block = $iv ^ substr($plaintext, $i);
                    $iv = substr_replace($iv, $block, 0, $len);
                    $ciphertext.= $block;
                    $pos = $len;
                }
                return $ciphertext;
            }

            if (!$this->continuousBuffer) {
                mcrypt_generic_init($this->enmcrypt, $this->key, $this->encryptIV);
            }

            return $ciphertext;
        }

        if (strlen($this->key) <= 8) {
            $this->des[0]->mode = $this->mode;

            return $this->des[0]->encrypt($plaintext);
        }

        if ($this->use_inline_crypt) {
            $inline = $this->inline_crypt;
            return $inline('encrypt', $this, $plaintext);
        }

        $des = $this->des;

        $buffer = &$this->enbuffer;
        $continuousBuffer = $this->continuousBuffer;
        $ciphertext = '';
        switch ($this->mode) {
            case CRYPT_DES_MODE_ECB:
                for ($i = 0; $i < strlen($plaintext); $i+=8) {
                    $block = substr($plaintext, $i, 8);
                    // all of these _processBlock calls could, in theory, be put in a function - say Crypt_TripleDES::_ede_encrypt() or something.
                    // only problem with that: it would slow encryption and decryption down.  $this->des would have to be called every time that
                    // function is called, instead of once for the whole string of text that's being encrypted, which would, in turn, make 
                    // encryption and decryption take more time, per this:
                    //
                    // http://blog.libssh2.org/index.php?/archives/21-Compiled-Variables.html
                    $block = $des[0]->_processBlock($block, CRYPT_DES_ENCRYPT);
                    $block = $des[1]->_processBlock($block, CRYPT_DES_DECRYPT);
                    $block = $des[2]->_processBlock($block, CRYPT_DES_ENCRYPT);
                    $ciphertext.= $block;
                }
                break;
            case CRYPT_DES_MODE_CBC:
                $xor = $this->encryptIV;
                for ($i = 0; $i < strlen($plaintext); $i+=8) {
                    $block = substr($plaintext, $i, 8) ^ $xor;
                    $block = $des[0]->_processBlock($block, CRYPT_DES_ENCRYPT);
                    $block = $des[1]->_processBlock($block, CRYPT_DES_DECRYPT);
                    $block = $des[2]->_processBlock($block, CRYPT_DES_ENCRYPT);
                    $xor = $block;
                    $ciphertext.= $block;
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                }
                break;
            case CRYPT_DES_MODE_CTR:
                $xor = $this->encryptIV;
                if (strlen($buffer['encrypted'])) {
                    for ($i = 0; $i < strlen($plaintext); $i+=8) {
                        $block = substr($plaintext, $i, 8);
                        if (strlen($block) > strlen($buffer['encrypted'])) {
                            $key = $this->_generate_xor($xor);
                            $key = $des[0]->_processBlock($key, CRYPT_DES_ENCRYPT);
                            $key = $des[1]->_processBlock($key, CRYPT_DES_DECRYPT);
                            $key = $des[2]->_processBlock($key, CRYPT_DES_ENCRYPT);
                            $buffer['encrypted'].= $key;
                        }
                        $key = $this->_string_shift($buffer['encrypted']);
                        $ciphertext.= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($plaintext); $i+=8) {
                        $block = substr($plaintext, $i, 8);
                        $key = $this->_generate_xor($xor);
                        $key = $des[0]->_processBlock($key, CRYPT_DES_ENCRYPT);
                        $key = $des[1]->_processBlock($key, CRYPT_DES_DECRYPT);
                        $key = $des[2]->_processBlock($key, CRYPT_DES_ENCRYPT);
                        $ciphertext.= $block ^ $key;
                    }
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                    if ($start = strlen($plaintext) & 7) {
                        $buffer['encrypted'] = substr($key, $start) . $buffer['encrypted'];
                    }
                }
                break;
            case CRYPT_DES_MODE_CFB:
                if (strlen($buffer['xor'])) {
                    $ciphertext = $plaintext ^ $buffer['xor'];
                    $iv = $buffer['encrypted'] . $ciphertext;
                    $start = strlen($ciphertext);
                    $buffer['encrypted'].= $ciphertext;
                    $buffer['xor'] = substr($buffer['xor'], strlen($ciphertext));
                } else {
                    $ciphertext = '';
                    $iv = $this->encryptIV;
                    $start = 0;
                }

                for ($i = $start; $i < strlen($plaintext); $i+=8) {
                    $block = substr($plaintext, $i, 8);
                    $iv = $des[0]->_processBlock($iv, CRYPT_DES_ENCRYPT);
                    $iv = $des[1]->_processBlock($iv, CRYPT_DES_DECRYPT);
                    $xor= $des[2]->_processBlock($iv, CRYPT_DES_ENCRYPT);

                    $iv = $block ^ $xor;
                    if ($continuousBuffer && strlen($iv) != 8) {
                        $buffer = array(
                            'encrypted' => $iv,
                            'xor' => substr($xor, strlen($iv))
                        );
                    }
                    $ciphertext.= $iv;
                }

                if ($this->continuousBuffer) {
                    $this->encryptIV = $iv;
                }
                break;
            case CRYPT_DES_MODE_OFB:
                $xor = $this->encryptIV;
                if (strlen($buffer['xor'])) {
                    for ($i = 0; $i < strlen($plaintext); $i+=8) {
                        $block = substr($plaintext, $i, 8);
                        if (strlen($block) > strlen($buffer['xor'])) {
                            $xor = $des[0]->_processBlock($xor, CRYPT_DES_ENCRYPT);
                            $xor = $des[1]->_processBlock($xor, CRYPT_DES_DECRYPT);
                            $xor = $des[2]->_processBlock($xor, CRYPT_DES_ENCRYPT);
                            $buffer['xor'].= $xor;
                        }
                        $key = $this->_string_shift($buffer['xor']);
                        $ciphertext.= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($plaintext); $i+=8) {
                        $xor = $des[0]->_processBlock($xor, CRYPT_DES_ENCRYPT);
                        $xor = $des[1]->_processBlock($xor, CRYPT_DES_DECRYPT);
                        $xor = $des[2]->_processBlock($xor, CRYPT_DES_ENCRYPT);
                        $ciphertext.= substr($plaintext, $i, 8) ^ $xor;
                    }
                    $key = $xor;
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                    if ($start = strlen($plaintext) & 7) {
                         $buffer['xor'] = substr($key, $start) . $buffer['xor'];
                    }
                }
        }

        return $ciphertext;
    }

    /**
     * Decrypts a message.
     *
     * @access public
     * @param String $ciphertext
     */
    function decrypt($ciphertext)
    {
        if ($this->mode == CRYPT_DES_MODE_3CBC && strlen($this->key) > 8) {
            $plaintext = $this->des[0]->decrypt($this->des[1]->encrypt($this->des[2]->decrypt($ciphertext)));

            return $this->_unpad($plaintext);
        }

        if ($this->paddable) {
            // we pad with chr(0) since that's what mcrypt_generic does.  to quote from http://php.net/function.mcrypt-generic :
            // "The data is padded with "\0" to make sure the length of the data is n * blocksize."
            $ciphertext = str_pad($ciphertext, (strlen($ciphertext) + 7) & 0xFFFFFFF8, chr(0));
        }

        if ( CRYPT_DES_MODE == CRYPT_DES_MODE_MCRYPT ) {
            if ($this->dechanged) {
                mcrypt_generic_init($this->demcrypt, $this->key, $this->decryptIV);
                if ($this->mode == 'ncfb') {
                    mcrypt_generic_init($this->ecb, $this->key, "\0\0\0\0\0\0\0\0");
                }
                $this->dechanged = false;
            }

            if ($this->mode != 'ncfb' || !$this->continuousBuffer) {
                $plaintext = mdecrypt_generic($this->demcrypt, $ciphertext);
            } else {
                $iv = &$this->decryptIV;
                $pos = &$this->debuffer['pos'];
                $len = strlen($ciphertext);
                $plaintext = '';
                $i = 0;
                if ($pos) {
                    $orig_pos = $pos;
                    $max = 8 - $pos;
                    if ($len >= $max) {
                        $i = $max;
                        $len-= $max;
                        $pos = 0;
                    } else {
                        $i = $len;
                        $pos+= $len;
                        $len = 0;
                    }
                    $plaintext = substr($iv, $orig_pos) ^ $ciphertext;
                    $iv = substr_replace($iv, substr($ciphertext, 0, $i), $orig_pos, $i);
                }
                if ($len >= 8) {
                    $cb = substr($ciphertext, $i, $len - $len % 8);
                    $plaintext.= mcrypt_generic($this->ecb, $iv . $cb) ^ $cb;
                    $iv = substr($cb, -8);
                    $len%= 8;
                }
                if ($len) {
                    $iv = mcrypt_generic($this->ecb, $iv);
                    $cb = substr($ciphertext, -$len);
                    $plaintext.= $iv ^ $cb;
                    $iv = substr_replace($iv, $cb, 0, $len);
                    $pos = $len;
                }
                return $plaintext;
            }

            if (!$this->continuousBuffer) {
                mcrypt_generic_init($this->demcrypt, $this->key, $this->decryptIV);
            }

            return $this->paddable ? $this->_unpad($plaintext) : $plaintext;
        }

        if (strlen($this->key) <= 8) {
            $this->des[0]->mode = $this->mode;
            $plaintext = $this->des[0]->decrypt($ciphertext);
            return $this->paddable ? $this->_unpad($plaintext) : $plaintext;
        }

        if ($this->use_inline_crypt) {
            $inline = $this->inline_crypt;
            return $inline('decrypt', $this, $ciphertext);
        }

        $des = $this->des;

        $buffer = &$this->debuffer;
        $continuousBuffer = $this->continuousBuffer;
        $plaintext = '';
        switch ($this->mode) {
            case CRYPT_DES_MODE_ECB:
                for ($i = 0; $i < strlen($ciphertext); $i+=8) {
                    $block = substr($ciphertext, $i, 8);
                    $block = $des[2]->_processBlock($block, CRYPT_DES_DECRYPT);
                    $block = $des[1]->_processBlock($block, CRYPT_DES_ENCRYPT);
                    $block = $des[0]->_processBlock($block, CRYPT_DES_DECRYPT);
                    $plaintext.= $block;
                }
                break;
            case CRYPT_DES_MODE_CBC:
                $xor = $this->decryptIV;
                for ($i = 0; $i < strlen($ciphertext); $i+=8) {
                    $orig = $block = substr($ciphertext, $i, 8);
                    $block = $des[2]->_processBlock($block, CRYPT_DES_DECRYPT);
                    $block = $des[1]->_processBlock($block, CRYPT_DES_ENCRYPT);
                    $block = $des[0]->_processBlock($block, CRYPT_DES_DECRYPT);
                    $plaintext.= $block ^ $xor;
                    $xor = $orig;
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                }
                break;
            case CRYPT_DES_MODE_CTR:
                $xor = $this->decryptIV;
                if (strlen($buffer['ciphertext'])) {
                    for ($i = 0; $i < strlen($ciphertext); $i+=8) {
                        $block = substr($ciphertext, $i, 8);
                        if (strlen($block) > strlen($buffer['ciphertext'])) {
                            $key = $this->_generate_xor($xor);
                            $key = $des[0]->_processBlock($key, CRYPT_DES_ENCRYPT);
                            $key = $des[1]->_processBlock($key, CRYPT_DES_DECRYPT);
                            $key = $des[2]->_processBlock($key, CRYPT_DES_ENCRYPT);
                            $buffer['ciphertext'].= $key;
                        }
                        $key = $this->_string_shift($buffer['ciphertext']);
                        $plaintext.= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($ciphertext); $i+=8) {
                        $block = substr($ciphertext, $i, 8);
                        $key = $this->_generate_xor($xor);
                        $key = $des[0]->_processBlock($key, CRYPT_DES_ENCRYPT);
                        $key = $des[1]->_processBlock($key, CRYPT_DES_DECRYPT);
                        $key = $des[2]->_processBlock($key, CRYPT_DES_ENCRYPT);
                        $plaintext.= $block ^ $key;
                    }
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                    if ($start = strlen($plaintext) & 7) {
                        $buffer['ciphertext'] = substr($key, $start) . $buffer['ciphertext'];
                    }
                }
                break;
            case CRYPT_DES_MODE_CFB:
                if (strlen($buffer['ciphertext'])) {
                    $plaintext = $ciphertext ^ substr($this->decryptIV, strlen($buffer['ciphertext']));
                    $buffer['ciphertext'].= substr($ciphertext, 0, strlen($plaintext));
                    if (strlen($buffer['ciphertext']) != 8) {
                        $block = $this->decryptIV;
                    } else {
                        $block = $buffer['ciphertext'];
                        $xor = $des[0]->_processBlock($buffer['ciphertext'], CRYPT_DES_ENCRYPT);
                        $xor = $des[1]->_processBlock($xor, CRYPT_DES_DECRYPT);
                        $xor = $des[2]->_processBlock($xor, CRYPT_DES_ENCRYPT);
                        $buffer['ciphertext'] = '';
                    }
                    $start = strlen($plaintext);
                } else {
                    $plaintext = '';
                    $xor = $des[0]->_processBlock($this->decryptIV, CRYPT_DES_ENCRYPT);
                    $xor = $des[1]->_processBlock($xor, CRYPT_DES_DECRYPT);
                    $xor = $des[2]->_processBlock($xor, CRYPT_DES_ENCRYPT);
                    $start = 0;
                }

                for ($i = $start; $i < strlen($ciphertext); $i+=8) {
                    $block = substr($ciphertext, $i, 8);
                    $plaintext.= $block ^ $xor;
                    if ($continuousBuffer && strlen($block) != 8) {
                        $buffer['ciphertext'].= $block;
                        $block = $xor;
                    } else if (strlen($block) == 8) {
                        $xor = $des[0]->_processBlock($block, CRYPT_DES_ENCRYPT);
                        $xor = $des[1]->_processBlock($xor, CRYPT_DES_DECRYPT);
                        $xor = $des[2]->_processBlock($xor, CRYPT_DES_ENCRYPT);
                    }
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $block;
                }
                break;
            case CRYPT_DES_MODE_OFB:
                $xor = $this->decryptIV;
                if (strlen($buffer['xor'])) {
                    for ($i = 0; $i < strlen($ciphertext); $i+=8) {
                        $block = substr($ciphertext, $i, 8);
                        if (strlen($block) > strlen($buffer['xor'])) {
                            $xor = $des[0]->_processBlock($xor, CRYPT_DES_ENCRYPT);
                            $xor = $des[1]->_processBlock($xor, CRYPT_DES_DECRYPT);
                            $xor = $des[2]->_processBlock($xor, CRYPT_DES_ENCRYPT);
                            $buffer['xor'].= $xor;
                        }
                        $key = $this->_string_shift($buffer['xor']);
                        $plaintext.= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($ciphertext); $i+=8) {
                        $xor = $des[0]->_processBlock($xor, CRYPT_DES_ENCRYPT);
                        $xor = $des[1]->_processBlock($xor, CRYPT_DES_DECRYPT);
                        $xor = $des[2]->_processBlock($xor, CRYPT_DES_ENCRYPT);
                        $plaintext.= substr($ciphertext, $i, 8) ^ $xor;
                    }
                    $key = $xor;
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                    if ($start = strlen($ciphertext) & 7) {
                         $buffer['xor'] = substr($key, $start) . $buffer['xor'];
                    }
                }
        }

        return $this->paddable ? $this->_unpad($plaintext) : $plaintext;
    }

    /**
     * Treat consecutive "packets" as if they are a continuous buffer.
     *
     * Say you have a 16-byte plaintext $plaintext.  Using the default behavior, the two following code snippets
     * will yield different outputs:
     *
     * <code>
     *    echo $des->encrypt(substr($plaintext, 0, 8));
     *    echo $des->encrypt(substr($plaintext, 8, 8));
     * </code>
     * <code>
     *    echo $des->encrypt($plaintext);
     * </code>
     *
     * The solution is to enable the continuous buffer.  Although this will resolve the above discrepancy, it creates
     * another, as demonstrated with the following:
     *
     * <code>
     *    $des->encrypt(substr($plaintext, 0, 8));
     *    echo $des->decrypt($des->encrypt(substr($plaintext, 8, 8)));
     * </code>
     * <code>
     *    echo $des->decrypt($des->encrypt(substr($plaintext, 8, 8)));
     * </code>
     *
     * With the continuous buffer disabled, these would yield the same output.  With it enabled, they yield different
     * outputs.  The reason is due to the fact that the initialization vector's change after every encryption /
     * decryption round when the continuous buffer is enabled.  When it's disabled, they remain constant.
     *
     * Put another way, when the continuous buffer is enabled, the state of the Crypt_DES() object changes after each
     * encryption / decryption round, whereas otherwise, it'd remain constant.  For this reason, it's recommended that
     * continuous buffers not be used.  They do offer better security and are, in fact, sometimes required (SSH uses them),
     * however, they are also less intuitive and more likely to cause you problems.
     *
     * @see Crypt_TripleDES::disableContinuousBuffer()
     * @access public
     */
    function enableContinuousBuffer()
    {
        $this->continuousBuffer = true;
        if ($this->mode == CRYPT_DES_MODE_3CBC) {
            $this->des[0]->enableContinuousBuffer();
            $this->des[1]->enableContinuousBuffer();
            $this->des[2]->enableContinuousBuffer();
        }
    }

    /**
     * Treat consecutive packets as if they are a discontinuous buffer.
     *
     * The default behavior.
     *
     * @see Crypt_TripleDES::enableContinuousBuffer()
     * @access public
     */
    function disableContinuousBuffer()
    {
        $this->continuousBuffer = false;
        $this->encryptIV = $this->iv;
        $this->decryptIV = $this->iv;
        $this->enchanged = true;
        $this->dechanged = true;
        $this->enbuffer = array('encrypted' => '', 'xor' => '', 'pos' => 0, 'enmcrypt_init' => true);
        $this->debuffer = array('ciphertext' => '', 'xor' => '', 'pos' => 0, 'demcrypt_init' => true);

        if ($this->mode == CRYPT_DES_MODE_3CBC) {
            $this->des[0]->disableContinuousBuffer();
            $this->des[1]->disableContinuousBuffer();
            $this->des[2]->disableContinuousBuffer();
        }
    }
}

// vim: ts=4:sw=4:et:
// vim6: fdl=1:
