<?php

/**
 * Pure-PHP implementation of AES.
 *
 * Uses mcrypt, if available/possible, and an internal implementation, otherwise.
 *
 * PHP versions 4 and 5
 *
 * If {@link Crypt\AES::setKeyLength() setKeyLength()} isn't called, it'll be calculated from
 * {@link Crypt\AES::setKey() setKey()}.  ie. if the key is 128-bits, the key length will be 128-bits.  If it's 136-bits
 * it'll be null-padded to 192-bits and 192 bits will be the key length until {@link Crypt\AES::setKey() setKey()}
 * is called, again, at which point, it'll be recalculated.
 *
 * Since Crypt\AES extends Crypt\Rijndael, some functions are available to be called that, in the context of AES, don't
 * make a whole lot of sense.  {@link Crypt\AES::setBlockLength() setBlockLength()}, for instance.  Calling that function,
 * however possible, won't do anything (AES has a fixed block length whereas Rijndael has a variable one).
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    $aes = new phpseclib\Crypt\AES();
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
 * @category  Crypt
 * @package   Crypt\AES
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright MMVIII Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt;

/**
 * Pure-PHP implementation of AES.
 *
 * @package Crypt\AES
 * @author  Jim Wigginton <terrafrost@php.net>
 * @version 0.1.0
 * @access  public
 */
class AES extends Rijndael
{
    /**
     * Default Constructor.
     *
     * Determines whether or not the mcrypt extension should be used.
     *
     * $mode could be:
     *
     * - AES::MODE_ECB
     *
     * - AES::MODE_CBC
     *
     * - AES::MODE_CTR
     *
     * - AES::MODE_CFB
     *
     * - AES::MODE_OFB
     *
     * If not explictly set, AES::MODE_CBC will be used.
     *
     * @see Crypt\Rijndael::Crypt\Rijndael()
     * @see Crypt\Base::__construct()
     * @param optional Integer $mode
     * @access public
     */
    function __construct($mode = AES::MODE_CBC)
    {
        parent::__construct($mode);
    }
    
    /**
     * Dummy function
     *
     * Since Crypt\AES extends Crypt\Rijndael, this function is, technically, available, but it doesn't do anything.
     *
     * @see Crypt\Rijndael::setBlockLength()
     * @access public
     * @param Integer $length
     */
    function setBlockLength($length)
    {
        return;
    }
}
