<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Base Class for all Crypt_* cipher classes
 *
 * PHP versions 4 and 5
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
 * @package    Crypt_Base
 * @author     Jim Wigginton <terrafrost@php.net>
 * @author     Hans-Juergen Petrich <petrich@tronic-media.com>
 * @copyright  MMVII Jim Wigginton
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @version    1.0
 * @link       http://phpseclib.sourceforge.net
 */

/**#@+
 * @access public
 * @see Crypt_Base::encrypt()
 * @see Crypt_Base::decrypt()
 */
/**
 * Encrypt / decrypt using the Counter mode.
 *
 * Set to -1 since that's what Crypt/Random.php uses to index the CTR mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
 */
define('CRYPT_MODE_CTR', -1);
/**
 * Encrypt / decrypt using the Electronic Code Book mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29
 */
define('CRYPT_MODE_ECB', 1);
/**
 * Encrypt / decrypt using the Code Book Chaining mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
 */
define('CRYPT_MODE_CBC', 2);
/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
 */
define('CRYPT_MODE_CFB', 3);
/**
 * Encrypt / decrypt using the Output Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29
 */
define('CRYPT_MODE_OFB', 4);
/**
 * Encrypt / decrypt using streaming mode.
 * 
 */
define('CRYPT_MODE_STREAM', 5);
/**#@-*/

/**#@+
 * @access private
 * @see Crypt_Base::Crypt_Base()
 */
/**
 * Base value for the internal implementation $engine switch
 */
define('CRYPT_MODE_INTERNAL', 1);
/**
 * Base value for the mcrypt implementation $engine switch
 */
define('CRYPT_MODE_MCRYPT', 2);
/**#@-*/

/**
 * Base Class for all Crypt_* cipher classes
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @author  Hans-Juergen Petrich <petrich@tronic-media.com>
 * @version 1.0.0
 * @access  public
 * @package Crypt_Base
 */
class Crypt_Base {
    /**
     * The Encryption Mode
     *
     * @see Crypt_Base::Crypt_Base()
     * @var Integer
     * @access private
     */
    var $mode;

    /**
     * The Block Length of the block cipher
     *
     * @var Integer
     * @access private
     */
    var $block_size = 16;

    /**
     * The Key
     *
     * @see Crypt_Base::setKey()
     * @var String
     * @access private
     */
    var $key = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    /**
     * The Initialization Vector
     *
     * @see Crypt_Base::setIV()
     * @var String
     * @access private
     */
    var $iv;

    /**
     * A "sliding" Initialization Vector
     *
     * @see Crypt_Base::enableContinuousBuffer()
     * @see Crypt_Base::_clearBuffers()
     * @var String
     * @access private
     */
    var $encryptIV;

    /**
     * A "sliding" Initialization Vector
     *
     * @see Crypt_Base::enableContinuousBuffer()
     * @see Crypt_Base::_clearBuffers()
     * @var String
     * @access private
     */
    var $decryptIV;

    /**
     * Continuous Buffer status
     *
     * @see Crypt_Base::enableContinuousBuffer()
     * @var Boolean
     * @access private
     */
    var $continuousBuffer = false;

    /**
     * Encryption buffer for CTR, OFB and CFB modes
     *
     * @see Crypt_Base::encrypt()
     * @see Crypt_Base::_clearBuffers()
     * @var Array
     * @access private
     */
    var $enbuffer;

    /**
     * Decryption buffer for CTR, OFB and CFB modes
     *
     * @see Crypt_Base::decrypt()
     * @see Crypt_Base::_clearBuffers()
     * @var Array
     * @access private
     */
    var $debuffer;

    /**
     * mcrypt resource for encryption
     *
     * The mcrypt resource can be recreated every time something needs to be created or it can be created just once.
     * Since mcrypt operates in continuous mode, by default, it'll need to be recreated when in non-continuous mode.
     *
     * @see Crypt_Base::encrypt()
     * @var Resource
     * @access private
     */
    var $enmcrypt;

    /**
     * mcrypt resource for decryption
     *
     * The mcrypt resource can be recreated every time something needs to be created or it can be created just once.
     * Since mcrypt operates in continuous mode, by default, it'll need to be recreated when in non-continuous mode.
     *
     * @see Crypt_Base::decrypt()
     * @var Resource
     * @access private
     */
    var $demcrypt;

    /**
     * Does the enmcrypt resource need to be (re)initialized?
     *
     * @see Crypt_Twofish::setKey()
     * @see Crypt_Twofish::setIV()
     * @var Boolean
     * @access private
     */
    var $enchanged = true;

    /**
     * Does the demcrypt resource need to be (re)initialized?
     *
     * @see Crypt_Twofish::setKey()
     * @see Crypt_Twofish::setIV()
     * @var Boolean
     * @access private
     */
    var $dechanged = true;

    /**
     * mcrypt resource for CFB mode
     *
     * mcrypt's CFB mode, in (and only in) buffered context,
     * is broken, so phpseclib implements the CFB mode by it self,
     * even when the mcrypt php extension is available.
     *
     * In order to do the CFB-mode work (fast) phpseclib
     * use a separate ECB-mode mcrypt resource.
     *
     * @link http://phpseclib.sourceforge.net/cfb-demo.phps
     * @see Crypt_Base::encrypt()
     * @see Crypt_Base::decrypt()
     * @see Crypt_Base::_mcryptSetup()
     * @var Resource
     * @access private
     */
    var $ecb;

    /**
     * Optimizing value while CFB-encrypting
     *
     * Only relevant if $continuousBuffer enabled
     * and $engine == CRYPT_MODE_MCRYPT
     *
     * It's faster to re-init $enmcrypt if
     * $buffer bytes > $cfb_init_len than
     * using the $ecb resource furthermore.
     *
     * This value depends of the choosen cipher
     * and the time it would be needed for it's
     * initialization [by mcrypt_generic_init()]
     * which, typically, depends on the complexity
     * on its internaly Key-expanding algorithm.
     *
     * @see Crypt_Base::encrypt()
     * @var Integer
     * @access private
     */
    var $cfb_init_len = 600;

    /**
     * Does internal cipher state need to be (re)initialized?
     *
     * @see setKey()
     * @see setIV()
     * @see disableContinuousBuffer()
     * @var Boolean
     * @access private
     */
    var $changed = true;

    /**
     * Padding status
     *
     * @see Crypt_Base::enablePadding()
     * @var Boolean
     * @access private
     */
    var $padding = true;

    /**
     * Is the mode one that is paddable?
     *
     * @see Crypt_Base::Crypt_Base()
     * @var Boolean
     * @access private
     */
    var $paddable = false;

    /**
     * Holds which crypt engine internaly should be use,
     * which will be determined automatically on __construct()
     *
     * Currently available $engines are:
     * - CRYPT_MODE_MCRYPT   (fast, php-extension: mcrypt, extension_loaded('mcrypt') required)
     * - CRYPT_MODE_INTERNAL (slower, pure php-engine, no php-extension required)
     *
     * In the pipeline... maybe. But currently not available:
     * - CRYPT_MODE_OPENSSL  (very fast, php-extension: openssl, extension_loaded('openssl') required)
     *
     * If possible, CRYPT_MODE_MCRYPT will be used for each cipher.
     * Otherwise CRYPT_MODE_INTERNAL
     *
     * @see Crypt_Base::encrypt()
     * @see Crypt_Base::decrypt()
     * @var Integer
     * @access private
     */
    var $engine;

    /**
     * The mcrypt specific name of the cipher
     *
     * Only used if $engine == CRYPT_MODE_MCRYPT
     *
     * @link http://www.php.net/mcrypt_module_open
     * @link http://www.php.net/mcrypt_list_algorithms
     * @see Crypt_Base::_mcryptSetup()
     * @var String
     * @access private
     */
    var $cipher_name_mcrypt;

    /**
     * The default password key_size used by setPassword()
     *
     * @see Crypt_Base::setPassword()
     * @var Integer
     * @access private
     */
    var $password_key_size = 32;

    /**
     * The default salt used by setPassword()
     *
     * @see Crypt_Base::setPassword()
     * @var String
     * @access private
     */
    var $password_default_salt = 'phpseclib/salt';

    /**
     * The namespace used by the cipher for its constants.
     *
     * ie: AES.php is using CRYPT_AES_MODE_* for its constants
     *     so $const_namespace is AES
     *
     *     DES.php is using CRYPT_DES_MODE_* for its constants
     *     so $const_namespace is DES... and so on
     *
     * All CRYPT_<$const_namespace>_MODE_* are aliases of
     * the generic CRYPT_MODE_* constants, so both could be used
     * for each cipher.
     *
     * Example:
     * $aes = new Crypt_AES(CRYPT_AES_MODE_CFB); // $aes will operate in cfb mode
     * $aes = new Crypt_AES(CRYPT_MODE_CFB);     // identical
     *
     * @see Crypt_Base::Crypt_Base()
     * @var String
     * @access private
     */
    var $const_namespace;

    /**
     * The name of the performance-optimized callback function
     *
     * Used by encrypt() / decrypt()
     * only if $engine == CRYPT_MODE_INTERNAL
     *
     * @see Crypt_Base::encrypt()
     * @see Crypt_Base::decrypt()
     * @see Crypt_Base::_inlineCryptSetup()
     * @see Crypt_Base::$use_inline_crypt
     * @var Callback
     * @access private
     */
    var $inline_crypt;

    /**
     * Holds whether performance-optimized $inline_crypt() can/should be used.
     *
     * @see Crypt_Base::encrypt()
     * @see Crypt_Base::decrypt()
     * @see Crypt_Base::inline_crypt
     * @var mixed
     * @access private
     */
    var $use_inline_crypt;

    /**
     * Default Constructor.
     *
     * Determines whether or not the mcrypt extension should be used.
     *
     * $mode could be:
     * - CRYPT_MODE_ECB
     * - CRYPT_MODE_CBC
     * - CRYPT_MODE_CTR
     * - CRYPT_MODE_CFB
     * - CRYPT_MODE_OFB
     * (or the alias constants of the choosen cipher, for example for AES: CRYPT_AES_MODE_ECB or CRYPT_AES_MODE_CBC ...)
     *
     * If not explictly set, CRYPT_MODE_CBC will be used.
     *
     * @param optional Integer $mode
     * @access public
     */
    function Crypt_Base($mode = CRYPT_MODE_CBC)
    {
        $const_crypt_mode = 'CRYPT_' . $this->const_namespace . '_MODE';

        // Determining the availibility of mcrypt support for the cipher
        if (!defined($const_crypt_mode)) {
            switch (true) {
                case extension_loaded('mcrypt') && in_array($this->cipher_name_mcrypt, mcrypt_list_algorithms()):
                    define($const_crypt_mode, CRYPT_MODE_MCRYPT);
                    break;
                default:
                    define($const_crypt_mode, CRYPT_MODE_INTERNAL);
            }
        }

        // Determining which internal $engine should be used.
        // The fastes possible first.
        switch (true) {
            case empty($this->cipher_name_mcrypt): // The cipher module has no mcrypt-engine support at all so we force CRYPT_MODE_INTERNAL
                $this->engine = CRYPT_MODE_INTERNAL;
                break;
            case constant($const_crypt_mode) == CRYPT_MODE_MCRYPT:
                $this->engine = CRYPT_MODE_MCRYPT;
                break;
            default:
                $this->engine = CRYPT_MODE_INTERNAL;
        }

        // $mode dependent settings
        switch ($mode) {
            case CRYPT_MODE_ECB:
                $this->paddable = true;
                $this->mode = $mode;
                break;
            case CRYPT_MODE_CTR:
            case CRYPT_MODE_CFB:
            case CRYPT_MODE_OFB:
            case CRYPT_MODE_STREAM:
                $this->mode = $mode;
                break;
            case CRYPT_MODE_CBC:
            default:
                $this->paddable = true;
                $this->mode = CRYPT_MODE_CBC;
        }

        // Determining whether inline crypting can be used by the cipher
        if ($this->use_inline_crypt !== false && function_exists('create_function')) {
            $this->use_inline_crypt = true;
        }
    }

    /**
     * Sets the initialization vector. (optional)
     *
     * SetIV is not required when CRYPT_MODE_ECB (or ie for AES: CRYPT_AES_MODE_ECB) is being used.  If not explictly set, it'll be assumed
     * to be all zero's.
     *
     * Note: Could, but not must, extend by the child Crypt_* class
     *
     * @access public
     * @param String $iv
     */
    function setIV($iv)
    {
        if ($this->mode == CRYPT_MODE_ECB) {
            return;
        }
        if ($this->iv === $iv) {
            return;
        }

        $this->iv = $iv;
        $this->changed = true;
    }

    /**
     * Sets the key.
     *
     * The min/max length(s) of the key depends on the cipher which is used.
     * If the key not fits the length(s) of the cipher it will paded with null bytes
     * up to the closest valid key length.  If the key is more than max length,
     * we trim the excess bits.
     *
     * If the key is not explicitly set, it'll be assumed to be all null bytes.
     *
     * Note: Could, but not must, extend by the child Crypt_* class
     *
     * @access public
     * @param String $key
     */
    function setKey($key)
    {
        if ($this->key === $key) {
            return;
        }

        $this->key = $key;
        $this->changed = true;
    }

    /**
     * Sets the password.
     *
     * Depending on what $method is set to, setPassword()'s (optional) parameters are as follows:
     *     {@link http://en.wikipedia.org/wiki/PBKDF2 pbkdf2}:
     *         $hash, $salt, $count, $dkLen
     *
     * Note: Could, but not must, extend by the child Crypt_* class
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
                $func_args = func_get_args();

                // Hash function
                $hash = isset($func_args[2]) ? $func_args[2] : 'sha1';

                // WPA and WPA2 use the SSID as the salt
                $salt = isset($func_args[3]) ? $func_args[3] : $this->password_default_salt;

                // RFC2898#section-4.2 uses 1,000 iterations by default
                // WPA and WPA2 use 4,096.
                $count = isset($func_args[4]) ? $func_args[4] : 1000;

                // Keylength
                $dkLen = isset($func_args[5]) ? $func_args[5] : $this->password_key_size;

                if (!class_exists('Crypt_Hash')) {
                    require_once('Crypt/Hash.php');
                }

                $i = 1;
                while (strlen($key) < $dkLen) {
                    $hmac = new Crypt_Hash();
                    $hmac->setHash($hash);
                    $hmac->setKey($password);
                    $f = $u = $hmac->hash($salt . pack('N', $i++));
                    for ($j = 2; $j <= $count; ++$j) {
                        $u = $hmac->hash($u);
                        $f^= $u;
                    }
                    $key.= $f;
                }
        }

        $this->setKey(substr($key, 0, $dkLen));
    }

    /**
     * Encrypts a message.
     *
     * $plaintext will be padded with additional bytes such that it's length is a multiple of the block size. Other cipher
     * implementations may or may not pad in the same manner.  Other common approaches to padding and the reasons why it's
     * necessary are discussed in the following
     * URL:
     *
     * {@link http://www.di-mgt.com.au/cryptopad.html http://www.di-mgt.com.au/cryptopad.html}
     *
     * An alternative to padding is to, separately, send the length of the file.  This is what SSH, in fact, does.
     * strlen($plaintext) will still need to be a multiple of the block size, however, arbitrary values can be added to make it that
     * length.
     *
     * Note: Could, but not must, extend by the child Crypt_* class
     *
     * @see Crypt_Base::decrypt()
     * @access public
     * @param String $plaintext
     * @return String $cipertext
     */
    function encrypt($plaintext)
    {
        if ($this->engine == CRYPT_MODE_MCRYPT) {
            if ($this->changed) {
                $this->_mcryptSetup();
                $this->changed = false;
            }
            if ($this->enchanged) {
                mcrypt_generic_init($this->enmcrypt, $this->key, $this->encryptIV);
                $this->enchanged = false;
            }

            // re: http://phpseclib.sourceforge.net/cfb-demo.phps
            // using mcrypt's default handing of CFB the above would output two different things.  using phpseclib's
            // rewritten CFB implementation the above outputs the same thing twice.
            if ($this->mode == CRYPT_MODE_CFB && $this->continuousBuffer) {
                $block_size = $this->block_size;
                $iv = &$this->encryptIV;
                $pos = &$this->enbuffer['pos'];
                $len = strlen($plaintext);
                $ciphertext = '';
                $i = 0;
                if ($pos) {
                    $orig_pos = $pos;
                    $max = $block_size - $pos;
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
                if ($len >= $block_size) {
                    if ($this->enbuffer['enmcrypt_init'] === false || $len > $this->cfb_init_len) {
                        if ($this->enbuffer['enmcrypt_init'] === true) {
                            mcrypt_generic_init($this->enmcrypt, $this->key, $iv);
                            $this->enbuffer['enmcrypt_init'] = false;
                        }
                        $ciphertext.= mcrypt_generic($this->enmcrypt, substr($plaintext, $i, $len - $len % $block_size));
                        $iv = substr($ciphertext, -$block_size);
                        $len%= $block_size;
                    } else {
                        while ($len >= $block_size) {
                            $iv = mcrypt_generic($this->ecb, $iv) ^ substr($plaintext, $i, $block_size);
                            $ciphertext.= $iv;
                            $len-= $block_size;
                            $i+= $block_size;
                        }
                    }
                }

                if ($len) {
                    $iv = mcrypt_generic($this->ecb, $iv);
                    $block = $iv ^ substr($plaintext, -$len);
                    $iv = substr_replace($iv, $block, 0, $len);
                    $ciphertext.= $block;
                    $pos = $len;
                }

                return $ciphertext;
            }

            if ($this->paddable) {
                $plaintext = $this->_pad($plaintext);
            }

            $ciphertext = mcrypt_generic($this->enmcrypt, $plaintext);

            if (!$this->continuousBuffer) {
                mcrypt_generic_init($this->enmcrypt, $this->key, $this->encryptIV);
            }

            return $ciphertext;
        }

        if ($this->changed) {
            $this->_setup();
            $this->changed = false;
        }
        if ($this->use_inline_crypt) {
            $inline = $this->inline_crypt;
            return $inline('encrypt', $this, $plaintext);
        }
        if ($this->paddable) {
            $plaintext = $this->_pad($plaintext);
        }

        $buffer = &$this->enbuffer;
        $block_size = $this->block_size;
        $ciphertext = '';
        switch ($this->mode) {
            case CRYPT_MODE_ECB:
                for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                    $ciphertext.= $this->_encryptBlock(substr($plaintext, $i, $block_size));
                }
                break;
            case CRYPT_MODE_CBC:
                $xor = $this->encryptIV;
                for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                    $block = substr($plaintext, $i, $block_size);
                    $block = $this->_encryptBlock($block ^ $xor);
                    $xor = $block;
                    $ciphertext.= $block;
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                }
                break;
            case CRYPT_MODE_CTR:
                $xor = $this->encryptIV;
                if (strlen($buffer['encrypted'])) {
                    for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                        $block = substr($plaintext, $i, $block_size);
                        if (strlen($block) > strlen($buffer['encrypted'])) {
                            $buffer['encrypted'].= $this->_encryptBlock($this->_generateXor($block_size, $xor));
                        }
                        $key = $this->_stringShift($buffer['encrypted'], $block_size);
                        $ciphertext.= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                        $block = substr($plaintext, $i, $block_size);
                        $key = $this->_encryptBlock($this->_generateXor($block_size, $xor));
                        $ciphertext.= $block ^ $key;
                    }
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                    if ($start = strlen($plaintext) % $block_size) {
                        $buffer['encrypted'] = substr($key, $start) . $buffer['encrypted'];
                    }
                }
                break;
            case CRYPT_MODE_CFB:
                // cfb loosely routines inspired by openssl's:
                // http://cvs.openssl.org/fileview?f=openssl/crypto/modes/cfb128.c&v=1.3.2.2.2.1
                if ($this->continuousBuffer) {
                    $iv = &$this->encryptIV;
                    $pos = &$buffer['pos'];
                } else {
                    $iv = $this->encryptIV;
                    $pos = 0;
                }
                $len = strlen($plaintext);
                $i = 0;
                if ($pos) {
                    $orig_pos = $pos;
                    $max = $block_size - $pos;
                    if ($len >= $max) {
                        $i = $max;
                        $len-= $max;
                        $pos = 0;
                    } else {
                        $i = $len;
                        $pos+= $len;
                        $len = 0;
                    }
                    // ie. $i = min($max, $len), $len-= $i, $pos+= $i, $pos%= $blocksize
                    $ciphertext = substr($iv, $orig_pos) ^ $plaintext;
                    $iv = substr_replace($iv, $ciphertext, $orig_pos, $i);
                }
                while ($len >= $block_size) {
                    $iv = $this->_encryptBlock($iv) ^ substr($plaintext, $i, $block_size);
                    $ciphertext.= $iv;
                    $len-= $block_size;
                    $i+= $block_size;
                }
                if ($len) {
                    $iv = $this->_encryptBlock($iv);
                    $block = $iv ^ substr($plaintext, $i);
                    $iv = substr_replace($iv, $block, 0, $len);
                    $ciphertext.= $block;
                    $pos = $len;
                }
                break;
            case CRYPT_MODE_OFB:
                $xor = $this->encryptIV;
                if (strlen($buffer['xor'])) {
                    for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                        $block = substr($plaintext, $i, $block_size);
                        if (strlen($block) > strlen($buffer['xor'])) {
                            $xor = $this->_encryptBlock($xor);
                            $buffer['xor'].= $xor;
                        }
                        $key = $this->_stringShift($buffer['xor'], $block_size);
                        $ciphertext.= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                        $xor = $this->_encryptBlock($xor);
                        $ciphertext.= substr($plaintext, $i, $block_size) ^ $xor;
                    }
                    $key = $xor;
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                    if ($start = strlen($plaintext) % $block_size) {
                         $buffer['xor'] = substr($key, $start) . $buffer['xor'];
                    }
                }
                break;
            case CRYPT_MODE_STREAM:
                $ciphertext = $this->_encryptBlock($plaintext);
                break;
        }

        return $ciphertext;
    }

    /**
     * Decrypts a message.
     *
     * If strlen($ciphertext) is not a multiple of the block size, null bytes will be added to the end of the string until
     * it is.
     *
     * Note: Could, but not must, extend by the child Crypt_* class
     *
     * @see Crypt_Base::encrypt()
     * @access public
     * @param String $ciphertext
     * @return String $plaintext
     */
    function decrypt($ciphertext)
    {
        if ($this->engine == CRYPT_MODE_MCRYPT) {
            $block_size = $this->block_size;
            if ($this->changed) {
                $this->_mcryptSetup();
                $this->changed = false;
            }
            if ($this->dechanged) {
                mcrypt_generic_init($this->demcrypt, $this->key, $this->decryptIV);
                $this->dechanged = false;
            }

            if ($this->mode == CRYPT_MODE_CFB && $this->continuousBuffer) {
                $iv = &$this->decryptIV;
                $pos = &$this->debuffer['pos'];
                $len = strlen($ciphertext);
                $plaintext = '';
                $i = 0;
                if ($pos) {
                    $orig_pos = $pos;
                    $max = $block_size - $pos;
                    if ($len >= $max) {
                        $i = $max;
                        $len-= $max;
                        $pos = 0;
                    } else {
                        $i = $len;
                        $pos+= $len;
                        $len = 0;
                    }
                    // ie. $i = min($max, $len), $len-= $i, $pos+= $i, $pos%= $blocksize
                    $plaintext = substr($iv, $orig_pos) ^ $ciphertext;
                    $iv = substr_replace($iv, substr($ciphertext, 0, $i), $orig_pos, $i);
                }
                if ($len >= $block_size) {
                    $cb = substr($ciphertext, $i, $len - $len % $block_size);
                    $plaintext.= mcrypt_generic($this->ecb, $iv . $cb) ^ $cb;
                    $iv = substr($cb, -$block_size);
                    $len%= $block_size;
                }
                if ($len) {
                    $iv = mcrypt_generic($this->ecb, $iv);
                    $plaintext.= $iv ^ substr($ciphertext, -$len);
                    $iv = substr_replace($iv, substr($ciphertext, -$len), 0, $len);
                    $pos = $len;
                }

                return $plaintext;
            }

            if ($this->paddable) {
                // we pad with chr(0) since that's what mcrypt_generic does.  to quote from http://php.net/function.mcrypt-generic :
                // "The data is padded with "\0" to make sure the length of the data is n * blocksize."
                $ciphertext = str_pad($ciphertext, strlen($ciphertext) + ($block_size - strlen($ciphertext) % $block_size) % $block_size, chr(0));
            }

            $plaintext = mdecrypt_generic($this->demcrypt, $ciphertext);

            if (!$this->continuousBuffer) {
                mcrypt_generic_init($this->demcrypt, $this->key, $this->decryptIV);
            }

            return $this->paddable ? $this->_unpad($plaintext) : $plaintext;
        }

        if ($this->changed) {
            $this->_setup();
            $this->changed = false;
        }
        if ($this->use_inline_crypt) {
            $inline = $this->inline_crypt;
            return $inline('decrypt', $this, $ciphertext);
        }

        $block_size = $this->block_size;
        if ($this->paddable) {
            // we pad with chr(0) since that's what mcrypt_generic does [...]
            $ciphertext = str_pad($ciphertext, strlen($ciphertext) + ($block_size - strlen($ciphertext) % $block_size) % $block_size, chr(0));
        }

        $buffer = &$this->debuffer;
        $plaintext = '';
        switch ($this->mode) {
            case CRYPT_MODE_ECB:
                for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                    $plaintext.= $this->_decryptBlock(substr($ciphertext, $i, $block_size));
                }
                break;
            case CRYPT_MODE_CBC:
                $xor = $this->decryptIV;
                for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                    $block = substr($ciphertext, $i, $block_size);
                    $plaintext.= $this->_decryptBlock($block) ^ $xor;
                    $xor = $block;
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                }
                break;
            case CRYPT_MODE_CTR:
                $xor = $this->decryptIV;
                if (strlen($buffer['ciphertext'])) {
                    for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                        $block = substr($ciphertext, $i, $block_size);
                        if (strlen($block) > strlen($buffer['ciphertext'])) {
                            $buffer['ciphertext'].= $this->_encryptBlock($this->_generateXor($block_size, $xor));
                        }
                        $key = $this->_stringShift($buffer['ciphertext'], $block_size);
                        $plaintext.= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                        $block = substr($ciphertext, $i, $block_size);
                        $key = $this->_encryptBlock($this->_generateXor($block_size, $xor));
                        $plaintext.= $block ^ $key;
                    }
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                    if ($start = strlen($ciphertext) % $block_size) {
                        $buffer['ciphertext'] = substr($key, $start) . $buffer['ciphertext'];
                    }
                }
                break;
            case CRYPT_MODE_CFB:
                if ($this->continuousBuffer) {
                    $iv = &$this->decryptIV;
                    $pos = &$buffer['pos'];
                } else {
                    $iv = $this->decryptIV;
                    $pos = 0;
                }
                $len = strlen($ciphertext);
                $i = 0;
                if ($pos) {
                    $orig_pos = $pos;
                    $max = $block_size - $pos;
                    if ($len >= $max) {
                        $i = $max;
                        $len-= $max;
                        $pos = 0;
                    } else {
                        $i = $len;
                        $pos+= $len;
                        $len = 0;
                    }
                    // ie. $i = min($max, $len), $len-= $i, $pos+= $i, $pos%= $blocksize
                    $plaintext = substr($iv, $orig_pos) ^ $ciphertext;
                    $iv = substr_replace($iv, substr($ciphertext, 0, $i), $orig_pos, $i);
                }
                while ($len >= $block_size) {
                    $iv = $this->_encryptBlock($iv);
                    $cb = substr($ciphertext, $i, $block_size);
                    $plaintext.= $iv ^ $cb;
                    $iv = $cb;
                    $len-= $block_size;
                    $i+= $block_size;
                }
                if ($len) {
                    $iv = $this->_encryptBlock($iv);
                    $plaintext.= $iv ^ substr($ciphertext, $i);
                    $iv = substr_replace($iv, substr($ciphertext, $i), 0, $len);
                    $pos = $len;
                }
                break;
            case CRYPT_MODE_OFB:
                $xor = $this->decryptIV;
                if (strlen($buffer['xor'])) {
                    for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                        $block = substr($ciphertext, $i, $block_size);
                        if (strlen($block) > strlen($buffer['xor'])) {
                            $xor = $this->_encryptBlock($xor);
                            $buffer['xor'].= $xor;
                        }
                        $key = $this->_stringShift($buffer['xor'], $block_size);
                        $plaintext.= $block ^ $key;
                    }
                } else {
                    for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                        $xor = $this->_encryptBlock($xor);
                        $plaintext.= substr($ciphertext, $i, $block_size) ^ $xor;
                    }
                    $key = $xor;
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                    if ($start = strlen($ciphertext) % $block_size) {
                         $buffer['xor'] = substr($key, $start) . $buffer['xor'];
                    }
                }
                break;
            case CRYPT_MODE_STREAM:
                $plaintext = $this->_decryptBlock($ciphertext);
                break;
        }
        return $this->paddable ? $this->_unpad($plaintext) : $plaintext;
    }

    /**
     * Pad "packets".
     *
     * Block ciphers working by encrypting between their specified [$this->]block_size at a time
     * If you ever need to encrypt or decrypt something that isn't of the proper length, it becomes necessary to
     * pad the input so that it is of the proper length.
     *
     * Padding is enabled by default.  Sometimes, however, it is undesirable to pad strings.  Such is the case in SSH,
     * where "packets" are padded with random bytes before being encrypted.  Unpad these packets and you risk stripping
     * away characters that shouldn't be stripped away. (SSH knows how many bytes are added because the length is
     * transmitted separately)
     *
     * @see Crypt_Base::disablePadding()
     * @access public
     */
    function enablePadding()
    {
        $this->padding = true;
    }

    /**
     * Do not pad packets.
     *
     * @see Crypt_Base::enablePadding()
     * @access public
     */
    function disablePadding()
    {
        $this->padding = false;
    }

    /**
     * Treat consecutive "packets" as if they are a continuous buffer.
     *
     * Say you have a 32-byte plaintext $plaintext.  Using the default behavior, the two following code snippets
     * will yield different outputs:
     *
     * <code>
     *    echo $rijndael->encrypt(substr($plaintext,  0, 16));
     *    echo $rijndael->encrypt(substr($plaintext, 16, 16));
     * </code>
     * <code>
     *    echo $rijndael->encrypt($plaintext);
     * </code>
     *
     * The solution is to enable the continuous buffer.  Although this will resolve the above discrepancy, it creates
     * another, as demonstrated with the following:
     *
     * <code>
     *    $rijndael->encrypt(substr($plaintext, 0, 16));
     *    echo $rijndael->decrypt($rijndael->encrypt(substr($plaintext, 16, 16)));
     * </code>
     * <code>
     *    echo $rijndael->decrypt($rijndael->encrypt(substr($plaintext, 16, 16)));
     * </code>
     *
     * With the continuous buffer disabled, these would yield the same output.  With it enabled, they yield different
     * outputs.  The reason is due to the fact that the initialization vector's change after every encryption /
     * decryption round when the continuous buffer is enabled.  When it's disabled, they remain constant.
     *
     * Put another way, when the continuous buffer is enabled, the state of the Crypt_*() object changes after each
     * encryption / decryption round, whereas otherwise, it'd remain constant.  For this reason, it's recommended that
     * continuous buffers not be used.  They do offer better security and are, in fact, sometimes required (SSH uses them),
     * however, they are also less intuitive and more likely to cause you problems.
     *
     * Note: Could, but not must, extend by the child Crypt_* class
     *
     * @see Crypt_Base::disableContinuousBuffer()
     * @access public
     */
    function enableContinuousBuffer()
    {
        if ($this->mode == CRYPT_MODE_ECB) {
            return;
        }

        $this->continuousBuffer = true;
    }

    /**
     * Treat consecutive packets as if they are a discontinuous buffer.
     *
     * The default behavior.
     *
     * Note: Could, but not must, extend by the child Crypt_* class
     *
     * @see Crypt_Base::enableContinuousBuffer()
     * @access public
     */
    function disableContinuousBuffer()
    {
        if ($this->mode == CRYPT_MODE_ECB) {
            return;
        }
        if (!$this->continuousBuffer) {
            return;
        }

        $this->continuousBuffer = false;
        $this->changed = true;
    }

    /**
     * Encrypts a block
     *
     * Note: Must extend by the child Crypt_* class
     *
     * @access private
     * @param String $in
     * @return String
     */
    function _encryptBlock($in)
    {
        echo basename(dirname(__FILE__)) .  '/' . basename(__FILE__) . ':' . __LINE__ . ' ' . ( version_compare(PHP_VERSION, '5.0.0', '>=')  ? __METHOD__ : __FUNCTION__ )  . '() must extend by ' . get_class($this);
    }

    /**
     * Decrypts a block
     *
     * Note: Must extend by the child Crypt_* class
     *
     * @access private
     * @param String $in
     * @return String
     */
    function _decryptBlock($in)
    {
        echo basename(dirname(__FILE__)) .  '/' . basename(__FILE__) . ':' . __LINE__ . ' ' . ( version_compare(PHP_VERSION, '5.0.0', '>=')  ? __METHOD__ : __FUNCTION__ )  . '() must extend by ' . get_class($this);
    }

    /**
     * Setup the CRYPT_MODE_INTERNAL $engine
     *
     * (re)init, if necessary, the internal cipher $engine and flush all $buffers
     * Used (only) if $engine == CRYPT_MODE_INTERNAL
     *
     * _setup() will be called each time if $changed === true
     * typically this happens when using one or more of following public methods:
     * - setKey()
     * - setIV()
     * - disableContinuousBuffer()
     * - First run of encrypt() / decrypt() with no init-settings
     *
     * Internally: _setup() will, if necessary always called before(!) en/decryption.
     *
     * Note: Could, but not must, extend by the child Crypt_* class
     *
     * @see setKey()
     * @see setIV()
     * @see disableContinuousBuffer()
     * @access private
     */
    function _setup()
    {
        $this->_clearBuffers();
        $this->_setupKey();

        if ($this->use_inline_crypt) {
            $this->_inlineCryptSetup();
        }
    }

    /**
     * Setup the CRYPT_MODE_MCRYPT $engine
     *
     * (re)init, if necessary, the (ext)mcrypt resources and flush all $buffers
     * Used (only) if $engine = CRYPT_MODE_MCRYPT
     *
     * _mcryptSetup() will be called each time if $changed === true
     * typically this happens when using one or more of following public methods:
     * - setKey()
     * - setIV()
     * - disableContinuousBuffer()
     * - First run of encrypt() / decrypt()
     *
     * Note: Could, but not must, extend by the child Crypt_* class
     *
     * @see setKey()
     * @see setIV()
     * @see disableContinuousBuffer()
     * @access private
     */
    function _mcryptSetup()
    {
        $this->_clearBuffers();
        $this->enchanged = $this->dechanged = true;

        if (!isset($this->enmcrypt)) {
            static $mcrypt_modes = array(
                CRYPT_MODE_CTR    => 'ctr',
                CRYPT_MODE_ECB    => MCRYPT_MODE_ECB,
                CRYPT_MODE_CBC    => MCRYPT_MODE_CBC,
                CRYPT_MODE_CFB    => 'ncfb',
                CRYPT_MODE_OFB    => MCRYPT_MODE_NOFB,
                CRYPT_MODE_STREAM => MCRYPT_MODE_STREAM,
            );

            $this->demcrypt = mcrypt_module_open($this->cipher_name_mcrypt, '', $mcrypt_modes[$this->mode], '');
            $this->enmcrypt = mcrypt_module_open($this->cipher_name_mcrypt, '', $mcrypt_modes[$this->mode], '');

            if ($this->mode == CRYPT_MODE_CFB) {
                $this->ecb = mcrypt_module_open($this->cipher_name_mcrypt, '', MCRYPT_MODE_ECB, '');
            }

        } // else should mcrypt_generic_deinit be called?

        if ($this->mode == CRYPT_MODE_CFB) {
            mcrypt_generic_init($this->ecb, $this->key, str_repeat("\0", $this->block_size));
        }
    }

    /**
     * Setup the key (expansion)
     *
     * Only used if $engine == CRYPT_MODE_INTERNAL
     *
     * Note: Must extend by the child Crypt_* class
     *
     * @see Crypt_Base::_setup()
     * @access private
     */
    function _setupKey()
    {
        echo basename(dirname(__FILE__)) .  '/' . basename(__FILE__) . ':' . __LINE__ . ' ' . ( version_compare(PHP_VERSION, '5.0.0', '>=')  ? __METHOD__ : __FUNCTION__ )  . '() must extend by ' . get_class($this);
    }

    /**
     * Pads a string
     *
     * Pads a string using the RSA PKCS padding standards so that its length is a multiple of the blocksize.
     * $this->block_size - (strlen($text) % $this->block_size) bytes are added, each of which is equal to
     * chr($this->block_size - (strlen($text) % $this->block_size)
     *
     * If padding is disabled and $text is not a multiple of the blocksize, the string will be padded regardless
     * and padding will, hence forth, be enabled.
     *
     * @see Crypt_Base::_unpad()
     * @param String $text
     * @access private
     */
    function _pad($text)
    {
        $length = strlen($text);

        if (!$this->padding) {
            if ($length % $this->block_size == 0) {
                return $text;
            } else {
                user_error("The plaintext's length ($length) is not a multiple of the block size ({$this->block_size})");
                $this->padding = true;
            }
        }

        $pad = $this->block_size - ($length % $this->block_size);

        return str_pad($text, $length + $pad, chr($pad));
    }

    /**
     * Unpads a string.
     *
     * If padding is enabled and the reported padding length is invalid the encryption key will be assumed to be wrong
     * and false will be returned.
     *
     * @see Crypt_Base::_pad()
     * @param String $text
     * @access private
     */
    function _unpad($text)
    {
        if (!$this->padding) {
            return $text;
        }

        $length = ord($text[strlen($text) - 1]);

        if (!$length || $length > $this->block_size) {
            return false;
        }

        return substr($text, 0, -$length);
    }

    /**
     * Clears internal buffers
     *
     * Clearing/resetting the internal buffers is done everytime
     * after disableContinuousBuffer() or on cipher $engine (re)init
     * ie after setKey() or setIV()
     *
     * Note: Could, but not must, extend by the child Crypt_* class
     *
     * @access public
     */
    function _clearBuffers()
    {
        $this->enbuffer = array('encrypted'  => '', 'xor' => '', 'pos' => 0, 'enmcrypt_init' => true);
        $this->debuffer = array('ciphertext' => '', 'xor' => '', 'pos' => 0, 'demcrypt_init' => true);

        // mcrypt's handling of invalid's $iv:
        // $this->encryptIV = $this->decryptIV = strlen($this->iv) == $this->block_size ? $this->iv : str_repeat("\0", $this->block_size);
        $this->encryptIV = $this->decryptIV = str_pad(substr($this->iv, 0, $this->block_size), $this->block_size, "\0");
    }

    /**
     * String Shift
     *
     * Inspired by array_shift
     *
     * @param String $string
     * @param optional Integer $index
     * @return String
     * @access private
     */
    function _stringShift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }

    /**
     * Generate CTR XOR encryption key
     *
     * Encrypt the output of this and XOR it against the ciphertext / plaintext to get the
     * plaintext / ciphertext in CTR mode.
     *
     * @see Crypt_Base::decrypt()
     * @see Crypt_Base::encrypt()
     * @access public
     * @param Integer $length
     * @param String $iv
     */
    function _generateXor($length, &$iv)
    {
        $xor = '';
        $block_size = $this->block_size;
        $num_blocks = floor(($length + ($block_size - 1)) / $block_size);
        for ($i = 0; $i < $num_blocks; $i++) {
            $xor.= $iv;
            for ($j = 4; $j <= $block_size; $j+= 4) {
                $temp = substr($iv, -$j, 4);
                switch ($temp) {
                    case "\xFF\xFF\xFF\xFF":
                        $iv = substr_replace($iv, "\x00\x00\x00\x00", -$j, 4);
                        break;
                    case "\x7F\xFF\xFF\xFF":
                        $iv = substr_replace($iv, "\x80\x00\x00\x00", -$j, 4);
                        break 2;
                    default:
                        extract(unpack('Ncount', $temp));
                        $iv = substr_replace($iv, pack('N', $count + 1), -$j, 4);
                        break 2;
                }
            }
        }

        return $xor;
    }

    /**
     * Setup the performance-optimized function for de/encrypt()
     *
     * Stores the created (or existing) callback function-name
     * in $this->inline_crypt
     *
     * Internally for phpseclib developers:
     *
     *     _inlineCryptSetup() would be called only if:
     *
     *     - $engine == CRYPT_MODE_INTERNAL and
     *     
     *     - $use_inline_crypt === true
     *     
     *     - each time on _setup(), after(!) _setupKey()
     *
     *     
     *     This ensures that _inlineCryptSetup() has allways a
     *     full ready2go initializated internal cipher $engine state
     *     where, for example, the keys allready expanded,
     *     keys/block_size calculated and such.
     *
     *     It is, each time if called, the responsibility of _inlineCryptSetup():
     *     
     *     - to set $this->inline_crypt to a valid and fully working callback function
     *       as a (faster) replacement for encrypt() / decrypt()
     *
     *     - NOT to create unlimited callback functions (for memory reasons!)
     *       no matter how often _inlineCryptSetup() would be called. At some
     *       point of amount they must be generic re-useable.
     *
     *     - the code of _inlineCryptSetup() it self,
     *       and the generated callback code,
     *       must be, in following order:
     *       - 100% safe
     *       - 100% compatible to encrypt()/decrypt()
     *       - using only php5+ features/lang-constructs/php-extensions if
     *         compatibility (down to php4) or fallback is provided
     *       - readable/maintainable/understandable/commented and... not-cryptic-styled-code :-)
     *       - >= 10% faster than encrypt()/decrypt() [which is, by the way,
     *         the reason for the existence of _inlineCryptSetup() :-)]
     *       - memory-nice
     *       - short (as good as possible)
     *
     * Note: _inlineCryptSetup() is using _createInlineCryptFunction() to create the full callback function code.
     *
     * Note: In case of using inline crypting, it must extend by the child Crypt_* class
     *
     * @see Crypt_Base::_setup()
     * @see Crypt_Base::_createInlineCryptFunction()
     * @see Crypt_Base::encrypt()
     * @see Crypt_Base::decrypt()
     * @access private
     */
    function _inlineCryptSetup()
    {
        // If a Crypt_* class providing inline crypting it must extend _inlineCryptSetup()

        // If, for any reason, an extending Crypt_Base() Crypt_* class
        // not using inline crypting then it must be ensured that: $this->use_inline_crypt = false
        // ie in the class var declaration of $use_inline_crypt in general for the Crypt_* class,
        // in the constructor at object instance-time
        // or, if it's runtime-specific, at runtime

        $this->use_inline_crypt = false;
    }

    /**
     * Creates the performance-optimized function for en/decrypt()
     *
     * Internally for phpseclib developers:
     *
     *    _createInlineCryptFunction():
     *
     *    - merge the $cipher_code [setup'ed by _inlineCryptSetup()]
     *      with the current [$this->]mode of operation code
     *
     *    - create the $inline function, which called by encrypt() / decrypt()
     *      as its replacement to speed up the en/decryption operations.
     *
     *    - return the name of the created $inline callback function
     *
     *    - used to speed up en/decryption
     *
     *
     *
     *    The main reason why can speed up things [up to 50%] this way are:
     *
     *    - using variables more effective then regular.
     *      (ie no use of expensive arrays but integers $k_0, $k_1 ...
     *      or even, for example, the pure $key[] values hardcoded)
     *
     *    - avoiding 1000's of function calls of ie _encryptBlock()
     *      but inlining the crypt operations.
     *      in the mode of operation for() loop.
     *
     *    - full loop unroll the (sometimes key-dependent) rounds
     *      avoiding this way ++$i counters and runtime-if's etc...
     *
     *    The basic code architectur of the generated $inline en/decrypt()
     *    lambda function, in pseudo php, is:
     *
     *    <code>
     *    +----------------------------------------------------------------------------------------------+
     *    | callback $inline = create_function:                                                          |
     *    | lambda_function_0001_crypt_ECB($action, $text)                                               |
     *    | {                                                                                            |
     *    |     INSERT PHP CODE OF:                                                                      |
     *    |     $cipher_code['init_crypt'];                  // general init code.                       |
     *    |                                                  // ie: $sbox'es declarations used for       |
     *    |                                                  //     encrypt and decrypt'ing.             |
     *    |                                                                                              |
     *    |     switch ($action) {                                                                       |
     *    |         case 'encrypt':                                                                      |
     *    |             INSERT PHP CODE OF:                                                              |
     *    |             $cipher_code['init_encrypt'];       // encrypt sepcific init code.               |
     *    |                                                    ie: specified $key or $box                |
     *    |                                                        declarations for encrypt'ing.         |
     *    |                                                                                              |
     *    |             foreach ($ciphertext) {                                                          |
     *    |                 $in = $block_size of $ciphertext;                                            |
     *    |                                                                                              |
     *    |                 INSERT PHP CODE OF:                                                          |
     *    |                 $cipher_code['encrypt_block'];  // encrypt's (string) $in, which is always:  |
     *    |                                                 // strlen($in) == $this->block_size          |
     *    |                                                 // here comes the cipher algorithm in action |
     *    |                                                 // for encryption.                           |
     *    |                                                                                              |
     *    |                 $plaintext .= $in;                                                           |
     *    |             }                                                                                |
     *    |             return $plaintext;                                                               |
     *    |                                                                                              |
     *    |         case 'decrypt':                                                                      |
     *    |             INSERT PHP CODE OF:                                                              |
     *    |             $cipher_code['init_decrypt'];       // decrypt sepcific init code                |
     *    |                                                    ie: specified $key or $box                |
     *    |                                                        declarations for decrypt'ing.         |
     *    |             foreach ($plaintext) {                                                           |
     *    |                 $in = $block_size of $plaintext;                                             |
     *    |                                                                                              |
     *    |                 INSERT PHP CODE OF:                                                          |
     *    |                 $cipher_code['decrypt_block'];  // decrypt's (string) $in, which is always   |
     *    |                                                 // strlen($in) == $this->block_size          |
     *    |                                                 // here comes the cipher algorithm in action |
     *    |                                                 // for decryption.                           |
     *    |                 $ciphertext .= $in;                                                          |
     *    |             }                                                                                |
     *    |             return $ciphertext;                                                              |
     *    |     }                                                                                        |
     *    | }                                                                                            |
     *    +----------------------------------------------------------------------------------------------+
     *    </code>
     *
     *    See also the Crypt_*::_inlineCryptSetup()'s for
     *    productive inline $cipher_code's how they works.
     *
     *    Structure of:
     *    <code>
     *    $cipher_code = array(
     *        'init_crypt'    => (string) '', // optional
     *        'init_encrypt'  => (string) '', // optional
     *        'init_decrypt'  => (string) '', // optional
     *        'encrypt_block' => (string) '', // required
     *        'decrypt_block' => (string) ''  // required
     *    );
     *    </code>
     *
     * @see Crypt_Base::_inlineCryptSetup()
     * @see Crypt_Base::encrypt()
     * @see Crypt_Base::decrypt()
     * @param Array $cipher_code
     * @access private
     * @return String (the name of the created callback function)
     */
    function _createInlineCryptFunction($cipher_code)
    {
        $block_size = $this->block_size;

        // optional
        $init_crypt    = isset($cipher_code['init_crypt'])    ? $cipher_code['init_crypt']    : '';
        $init_encrypt  = isset($cipher_code['init_encrypt'])  ? $cipher_code['init_encrypt']  : '';
        $init_decrypt  = isset($cipher_code['init_decrypt'])  ? $cipher_code['init_decrypt']  : '';
        // required
        $encrypt_block = $cipher_code['encrypt_block'];
        $decrypt_block = $cipher_code['decrypt_block'];

        // Generating mode of operation inline code,
        // merged with the $cipher_code algorithm
        // for encrypt- and decryption.
        switch ($this->mode) {
            case CRYPT_MODE_ECB:
                $encrypt = $init_encrypt . '
                    $ciphertext = "";
                    $text = $self->_pad($text);
                    $plaintext_len = strlen($text);

                    for ($i = 0; $i < $plaintext_len; $i+= '.$block_size.') {
                        $in = substr($text, $i, '.$block_size.');
                        '.$encrypt_block.'
                        $ciphertext.= $in;
                    }

                    return $ciphertext;
                    ';

                $decrypt = $init_decrypt . '
                    $plaintext = "";
                    $text = str_pad($text, strlen($text) + ('.$block_size.' - strlen($text) % '.$block_size.') % '.$block_size.', chr(0));
                    $ciphertext_len = strlen($text);

                    for ($i = 0; $i < $ciphertext_len; $i+= '.$block_size.') {
                        $in = substr($text, $i, '.$block_size.');
                        '.$decrypt_block.'
                        $plaintext.= $in;
                    }

                    return $self->_unpad($plaintext);
                    ';
                break;
            case CRYPT_MODE_CTR:
                $encrypt = $init_encrypt . '
                    $ciphertext = "";
                    $plaintext_len = strlen($text);
                    $xor = $self->encryptIV;
                    $buffer = &$self->enbuffer;

                    if (strlen($buffer["encrypted"])) {
                        for ($i = 0; $i < $plaintext_len; $i+= '.$block_size.') {
                            $block = substr($text, $i, '.$block_size.');
                            if (strlen($block) > strlen($buffer["encrypted"])) {
                                $in = $self->_generateXor('.$block_size.', $xor);
                                '.$encrypt_block.'
                                $buffer["encrypted"].= $in;
                            }
                            $key = $self->_stringShift($buffer["encrypted"], '.$block_size.');
                            $ciphertext.= $block ^ $key;
                        }
                    } else {
                        for ($i = 0; $i < $plaintext_len; $i+= '.$block_size.') {
                            $block = substr($text, $i, '.$block_size.');
                            $in = $self->_generateXor('.$block_size.', $xor);
                            '.$encrypt_block.'
                            $key = $in;
                            $ciphertext.= $block ^ $key;
                        }
                    }
                    if ($self->continuousBuffer) {
                        $self->encryptIV = $xor;
                        if ($start = $plaintext_len % '.$block_size.') {
                            $buffer["encrypted"] = substr($key, $start) . $buffer["encrypted"];
                        }
                    }

                    return $ciphertext;
                ';

                $decrypt = $init_encrypt . '
                    $plaintext = "";
                    $ciphertext_len = strlen($text);
                    $xor = $self->decryptIV;
                    $buffer = &$self->debuffer;

                    if (strlen($buffer["ciphertext"])) {
                        for ($i = 0; $i < $ciphertext_len; $i+= '.$block_size.') {
                            $block = substr($text, $i, '.$block_size.');
                            if (strlen($block) > strlen($buffer["ciphertext"])) {
                                $in = $self->_generateXor('.$block_size.', $xor);
                                '.$encrypt_block.'
                                $buffer["ciphertext"].= $in;
                            }
                            $key = $self->_stringShift($buffer["ciphertext"], '.$block_size.');
                            $plaintext.= $block ^ $key;
                        }
                    } else {
                        for ($i = 0; $i < $ciphertext_len; $i+= '.$block_size.') {
                            $block = substr($text, $i, '.$block_size.');
                            $in = $self->_generateXor('.$block_size.', $xor);
                            '.$encrypt_block.'
                            $key = $in;
                            $plaintext.= $block ^ $key;
                        }
                    }
                    if ($self->continuousBuffer) {
                        $self->decryptIV = $xor;
                        if ($start = $ciphertext_len % '.$block_size.') {
                            $buffer["ciphertext"] = substr($key, $start) . $buffer["ciphertext"];
                        }
                    }

                    return $plaintext;
                    ';
                break;
            case CRYPT_MODE_CFB:
                $encrypt = $init_encrypt . '
                    $ciphertext = "";
                    $buffer = &$self->enbuffer;

                    if ($self->continuousBuffer) {
                        $iv = &$self->encryptIV;
                        $pos = &$buffer["pos"];
                    } else {
                        $iv = $self->encryptIV;
                        $pos = 0;
                    }
                    $len = strlen($text);
                    $i = 0;
                    if ($pos) {
                        $orig_pos = $pos;
                        $max = '.$block_size.' - $pos;
                        if ($len >= $max) {
                            $i = $max;
                            $len-= $max;
                            $pos = 0;
                        } else {
                            $i = $len;
                            $pos+= $len;
                            $len = 0;
                        }
                        $ciphertext = substr($iv, $orig_pos) ^ $text;
                        $iv = substr_replace($iv, $ciphertext, $orig_pos, $i);
                    }
                    while ($len >= '.$block_size.') {
                        $in = $iv;
                        '.$encrypt_block.';
                        $iv = $in ^ substr($text, $i, '.$block_size.');
                        $ciphertext.= $iv;
                        $len-= '.$block_size.';
                        $i+= '.$block_size.';
                    }
                    if ($len) {
                        $in = $iv;
                        '.$encrypt_block.'
                        $iv = $in;
                        $block = $iv ^ substr($text, $i);
                        $iv = substr_replace($iv, $block, 0, $len);
                        $ciphertext.= $block;
                        $pos = $len;
                    }
                    return $ciphertext;
                ';

                $decrypt = $init_encrypt . '
                    $plaintext = "";
                    $buffer = &$self->debuffer;

                    if ($self->continuousBuffer) {
                        $iv = &$self->decryptIV;
                        $pos = &$buffer["pos"];
                    } else {
                        $iv = $self->decryptIV;
                        $pos = 0;
                    }
                    $len = strlen($text);
                    $i = 0;
                    if ($pos) {
                        $orig_pos = $pos;
                        $max = '.$block_size.' - $pos;
                        if ($len >= $max) {
                            $i = $max;
                            $len-= $max;
                            $pos = 0;
                        } else {
                            $i = $len;
                            $pos+= $len;
                            $len = 0;
                        }
                        $plaintext = substr($iv, $orig_pos) ^ $text;
                        $iv = substr_replace($iv, substr($text, 0, $i), $orig_pos, $i);
                    }
                    while ($len >= '.$block_size.') {
                        $in = $iv;
                        '.$encrypt_block.'
                        $iv = $in;
                        $cb = substr($text, $i, '.$block_size.');
                        $plaintext.= $iv ^ $cb;
                        $iv = $cb;
                        $len-= '.$block_size.';
                        $i+= '.$block_size.';
                    }
                    if ($len) {
                        $in = $iv;
                        '.$encrypt_block.'
                        $iv = $in;
                        $plaintext.= $iv ^ substr($text, $i);
                        $iv = substr_replace($iv, substr($text, $i), 0, $len);
                        $pos = $len;
                    }

                    return $plaintext;
                    ';
                break;
            case CRYPT_MODE_OFB:
                $encrypt = $init_encrypt . '
                    $ciphertext = "";
                    $plaintext_len = strlen($text);
                    $xor = $self->encryptIV;
                    $buffer = &$self->enbuffer;

                    if (strlen($buffer["xor"])) {
                        for ($i = 0; $i < $plaintext_len; $i+= '.$block_size.') {
                            $block = substr($text, $i, '.$block_size.');
                            if (strlen($block) > strlen($buffer["xor"])) {
                                $in = $xor;
                                '.$encrypt_block.'
                                $xor = $in;
                                $buffer["xor"].= $xor;
                            }
                            $key = $self->_stringShift($buffer["xor"], '.$block_size.');
                            $ciphertext.= $block ^ $key;
                        }
                    } else {
                        for ($i = 0; $i < $plaintext_len; $i+= '.$block_size.') {
                            $in = $xor;
                            '.$encrypt_block.'
                            $xor = $in;
                            $ciphertext.= substr($text, $i, '.$block_size.') ^ $xor;
                        }
                        $key = $xor;
                    }
                    if ($self->continuousBuffer) {
                        $self->encryptIV = $xor;
                        if ($start = $plaintext_len % '.$block_size.') {
                             $buffer["xor"] = substr($key, $start) . $buffer["xor"];
                        }
                    }
                    return $ciphertext;
                    ';

                $decrypt = $init_encrypt . '
                    $plaintext = "";
                    $ciphertext_len = strlen($text);
                    $xor = $self->decryptIV;
                    $buffer = &$self->debuffer;

                    if (strlen($buffer["xor"])) {
                        for ($i = 0; $i < $ciphertext_len; $i+= '.$block_size.') {
                            $block = substr($text, $i, '.$block_size.');
                            if (strlen($block) > strlen($buffer["xor"])) {
                                $in = $xor;
                                '.$encrypt_block.'
                                $xor = $in;
                                $buffer["xor"].= $xor;
                            }
                            $key = $self->_stringShift($buffer["xor"], '.$block_size.');
                            $plaintext.= $block ^ $key;
                        }
                    } else {
                        for ($i = 0; $i < $ciphertext_len; $i+= '.$block_size.') {
                            $in = $xor;
                            '.$encrypt_block.'
                            $xor = $in;
                            $plaintext.= substr($text, $i, '.$block_size.') ^ $xor;
                        }
                        $key = $xor;
                    }
                    if ($self->continuousBuffer) {
                        $self->decryptIV = $xor;
                        if ($start = $ciphertext_len % '.$block_size.') {
                             $buffer["xor"] = substr($key, $start) . $buffer["xor"];
                        }
                    }
                    return $plaintext;
                    ';
                break;
            case CRYPT_MODE_STREAM:
                $encrypt = $init_encrypt . '
                    $ciphertext = "";
                    '.$encrypt_block.'
                    return $ciphertext;
                    ';
                $decrypt = $init_decrypt . '
                    $plaintext = "";
                    '.$decrypt_block.'
                    return $plaintext;
                    ';
                break;
            // case CRYPT_MODE_CBC:
            default:
                $encrypt = $init_encrypt . '
                    $ciphertext = "";
                    $text = $self->_pad($text);
                    $plaintext_len = strlen($text);

                    $in = $self->encryptIV;

                    for ($i = 0; $i < $plaintext_len; $i+= '.$block_size.') {
                        $in = substr($text, $i, '.$block_size.') ^ $in;
                        '.$encrypt_block.'
                        $ciphertext.= $in;
                    }

                    if ($self->continuousBuffer) {
                        $self->encryptIV = $in;
                    }

                    return $ciphertext;
                    ';

                $decrypt = $init_decrypt . '
                    $plaintext = "";
                    $text = str_pad($text, strlen($text) + ('.$block_size.' - strlen($text) % '.$block_size.') % '.$block_size.', chr(0));
                    $ciphertext_len = strlen($text);

                    $iv = $self->decryptIV;

                    for ($i = 0; $i < $ciphertext_len; $i+= '.$block_size.') {
                        $in = $block = substr($text, $i, '.$block_size.');
                        '.$decrypt_block.'
                        $plaintext.= $in ^ $iv;
                        $iv = $block;
                    }

                    if ($self->continuousBuffer) {
                        $self->decryptIV = $iv;
                    }

                    return $self->_unpad($plaintext);
                    ';
                break;
        }

        // Create the $inline function and return its name as string. Ready to run!
        return create_function('$action, &$self, $text', $init_crypt . 'if ($action == "encrypt") { ' . $encrypt . ' } else { ' . $decrypt . ' }');
    }

    /**
     * Holds the lambda_functions table (classwide)
     *
     * Each name of the lambda function, created from
     * _inlineCryptSetup() && _createInlineCryptFunction()
     * is stored, classwide (!), here for reusing.
     *
     * The string-based index of $function is a classwide
     * uniqe value representing, at least, the $mode of
     * operation (or more... depends of the optimizing level)
     * for which $mode the lambda function was created.
     *
     * @return Array
     * @access private
     */
    function &_getLambdaFunctions()
    {
        static $functions = array();
        return $functions;
    }

    /**
     * Class destructor.
     *
     * Will be called, automatically, if you're using PHP5.  If you're using PHP4, call it yourself.  Only really
     * needs to be called if mcrypt is being used.
     *
     * @access public
     */
    function __destruct()
    {
        if ($this->engine == CRYPT_MODE_MCRYPT) {
            if (is_resource($this->enmcrypt)) {
                mcrypt_module_close($this->enmcrypt);
            }
            if (is_resource($this->demcrypt)) {
                mcrypt_module_close($this->demcrypt);
            }
            if (is_resource($this->ecb)) {
                mcrypt_module_close($this->ecb);
            }
        }
    }
}

// vim: ts=4:sw=4:et:
// vim6: fdl=1:
