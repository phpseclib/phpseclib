<?php

/**
 * Pure-PHP ASN.1 Parser
 *
 * PHP versions 4 and 5
 *
 * ASN.1 provides the semantics for data encoded using various schemes.  The most commonly
 * utilized scheme is DER or the "Distinguished Encoding Rules".  PEM's are base64 encoded
 * DER blobs.
 *
 * File_ASN1 decodes and encodes DER formatted messages and places them in a semantic context.
 *
 * Uses the 1988 ASN.1 syntax.
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
 * @category  File
 * @package   File_ASN1
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright MMXII Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

/**
 * ASN.1 Element
 *
 * Bypass normal encoding rules in File_ASN1::encodeDER()
 *
 * @package File_ASN1
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class File_ASN1_Element
{
    /**
     * Raw element value
     *
     * @var String
     * @access private
     */
    var $element;

    /**
     * Constructor
     *
     * @param String $encoded
     * @return File_ASN1_Element
     * @access public
     */
    function __construct($encoded)
    {
        $this->element = $encoded;
    }
}