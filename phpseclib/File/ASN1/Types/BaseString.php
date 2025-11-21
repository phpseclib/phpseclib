<?php

/**
 * ASN.1 Base String
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2012 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Types;

use phpseclib4\Exception\CharacterConversionException;

/**
 * ASN.1 Base String
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class BaseString implements BaseType
{
    use Common;

    public function __construct(public string $value)
    {
    }

    public function __toString(): string
    {
        return $this->value;
    }

    /**
     * String type conversion
     *
     * This is a lazy conversion, dealing only with character size.
     * No real conversion table is used.
     *
     * @return string
     */
    private function convert(string $class): self
    {
        if (!$this->isConvertable()) {
            throw new CharacterConversionException('Unable to convert - ' . static::CLASS . ' doesn\'t have a size constant associated with it');
        }
        //if (!defined("$class::SIZE")) {
        //    throw new \Exception("Unable to convert - $class doesn't have a size constant associated with it");
        //}

        $insize = static::SIZE;
        $outsize = $class::SIZE;
        $in = $this->value;

        // altho in theory the following could save some computational resources
        // doing so risks making phpseclib 3.0 give different output than phpseclib 4.0
        // when the underlying string type is malformed.
        // see, for example, the cert in the testPostalAddress() method. the id-at-organizationName
        // attribute for the subject DN isn't valid UTF-8 so converting UTF-8 to UTF-8 results in
        // an error whereas if you just omit the conversion process all together, as the following
        // code does, then no error is issued
        //if ($insize == $outsize) {
        //    return new $class($in);
        //}

        $inlength = strlen($in);
        $out = '';

        for ($i = 0; $i < $inlength;) {
            if ($inlength - $i < $insize) {
                throw new CharacterConversionException('Malformed string detected: Input string needs at least ' . ($insize - $inlength + $i) . ' more bytes');
            }

            // Get an input character as a 32-bit value.
            $c = ord($in[$i++]);
            switch (true) {
                case $insize == 4:
                    $c = ($c << 8) | ord($in[$i++]);
                    $c = ($c << 8) | ord($in[$i++]);
                    // fall-through
                case $insize == 2:
                    $c = ($c << 8) | ord($in[$i++]);
                    // fall-through
                case $insize == 1:
                    break;
                // only single byte UTF-8 characters have the first bit set to 1
                case ($c & 0x80) == 0x00:
                    break;
                case ($c & 0x40) == 0x00:
                    // "In a sequence of n octets, n>1, the initial octet has the n higher-order bits set to 1,
                    //  followed by a bit set to 0."
                    // -- https://datatracker.ietf.org/doc/html/rfc2279#section-2
                    throw new CharacterConversionException('Malformed UTF-8 string detected (AND with 0x40 != 0x00)');
                default:
                    $bit = 6;
                    do {
                        // $bit > 25 is because the most number of non-fixed bits one can have in a UTF-8 character is 31
                        // and 25 + 6 = 31
                        // $i >= $inlength is because we don't want to try to extract more characters than are actually in
                        // the input string
                        // (ord($in[$i]) & 0xC0) != 0x80 makes sure that the first two bits are 10 (as above)
                        // RFC2279#section-2 elaborates
                        if ($bit > 25 || $i >= $inlength || (ord($in[$i]) & 0xC0) != 0x80) {
                            throw new CharacterConversionException('Malformed UTF-8 string detected');
                        }
                        $c = ($c << 6) | (ord($in[$i++]) & 0x3F);
                        $bit += 5;
                        $mask = 1 << $bit;
                    } while ($c & $bit);
                    $c &= $mask - 1;
                    break;
            }

            // Convert and append the character to output string.
            $v = '';
            $origC = $c;
            switch (true) {
                case $outsize == 4:
                    $v .= chr($c & 0xFF);
                    $c >>= 8;
                    $v .= chr($c & 0xFF);
                    $c >>= 8;
                    // fall-through
                case $outsize == 2:
                    $v .= chr($c & 0xFF);
                    $c >>= 8;
                    // fall-through
                case $outsize == 1:
                    $v .= chr($c & 0xFF);
                    $c >>= 8;
                    if ($c) {
                        throw new CharacterConversionException('Character requiring ' . floor(log($origC, 2)) . ' bits found but only ' . ($outsize << 3) . ' bits are available per character in new format');
                    }
                    break;
                // 1 << 31 == 0x8000000. we do the former vs the latter because the latter doesn't work well on 32-bit PHP installs
                case ($c & (1 << 31)) != 0:
                    throw new CharacterConversionException('Character requiring 32 bits found but only 31 bits are available per character in new format');
                case $c >= 0x04000000:
                    $v .= chr(0x80 | ($c & 0x3F));
                    $c = ($c >> 6) | 0x04000000;
                    // fall-through
                case $c >= 0x00200000:
                    $v .= chr(0x80 | ($c & 0x3F));
                    $c = ($c >> 6) | 0x00200000;
                    // fall-through
                case $c >= 0x00010000:
                    $v .= chr(0x80 | ($c & 0x3F));
                    $c = ($c >> 6) | 0x00010000;
                    // fall-through
                case $c >= 0x00000800:
                    $v .= chr(0x80 | ($c & 0x3F));
                    $c = ($c >> 6) | 0x00000800;
                    // fall-through
                case $c >= 0x00000080:
                    $v .= chr(0x80 | ($c & 0x3F));
                    $c = ($c >> 6) | 0x000000C0;
                    // fall-through
                default:
                    $v .= chr($c);
            }
            $out .= strrev($v);
        }
        return new $class($out);
    }

    public function isConvertable(): bool
    {
        return defined('static::SIZE');
    }

    public function toUTF8String(): self
    {
        return $this->convert(UTF8String::CLASS);
    }

    public function toBMPString(): self
    {
        return $this->convert(BMPString::CLASS);
    }

    public function toUniversalString(): self
    {
        return $this->convert(UniversalString::CLASS);
    }

    public function toPrintableString(): self
    {
        return $this->convert(PrintableString::CLASS);
    }

    public function toTeletexString(): self
    {
        return $this->convert(TeletexString::CLASS);
    }

    public function toIA5String(): self
    {
        return $this->convert(IA5String::CLASS);
    }

    public function toVisibleString(): self
    {
        return $this->convert(VisibleString::CLASS);
    }
}
