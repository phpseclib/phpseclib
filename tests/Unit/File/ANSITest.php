<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\File\ANSI;

class Unit_File_ANSITest extends PhpseclibTestCase
{
    public function testCase1()
    {
        $str = "\x1B[07m"; // turn reverse video on
        $str.= "aaaaaaaaaaaaaaaaaa";
        $str.= "\x1B[10D"; // move cursor left 10 lines
        $str.= "\x1B[m"; // reset everything
        $str.= "bbb";

        $ansi = new ANSI();
        $ansi->appendString($str);

        $expected = '<pre width="80" style="color: white; background: black">';
        $expected.= '<span style="color: black"><span style="background: white">aaaaaaaa</span></span>';
        $expected.= 'bbb';
        $expected.= '<span style="color: black"><span style="background: white">aaaaaaa</span></span>';
        $expected.= '</pre>';

        $this->assertSame($ansi->getScreen(), $expected);
    }
}
