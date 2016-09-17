<?php

/**
 * Common ASN1 Functions
 *
 * PHP version 5
 *
 * @category  Common
 * @package   Functions\ASN1
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Common\Functions;

/**
 * Common ASN1 Functions
 *
 * @package Functions\ASN1
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class ASN1
{
    /**
     * DER-decode the length
     *
     * DER supports lengths up to (2**8)**127, however, we'll only support lengths up to (2**8)**4.  See
     * {@link http://itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#p=13 X.690 paragraph 8.1.3} for more information.
     *
     * @access public
     * @param string $string
     * @return int
     */
    static function decodeLength(&$string)
    {
        $length = ord(Strings::shift($string));
        if ($length & 0x80) { // definite length, long form
            $length&= 0x7F;
            $temp = Strings::shift($string, $length);
            list(, $length) = unpack('N', substr(str_pad($temp, 4, chr(0), STR_PAD_LEFT), -4));
        }
        return $length;
    }

    /**
     * DER-encode the length
     *
     * DER supports lengths up to (2**8)**127, however, we'll only support lengths up to (2**8)**4.  See
     * {@link http://itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#p=13 X.690 paragraph 8.1.3} for more information.
     *
     * @access public
     * @param int $length
     * @return string
     */
    static function encodeLength($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }
}
