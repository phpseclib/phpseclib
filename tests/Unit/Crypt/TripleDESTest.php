<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Base;
use phpseclib\Crypt\TripleDES;

class Unit_Crypt_TripleDESTest extends PhpseclibTestCase
{
    var $engines = array(
        Base::ENGINE_INTERNAL => 'internal',
        Base::ENGINE_MCRYPT => 'mcrypt',
        Base::ENGINE_OPENSSL => 'OpenSSL',
    );

    public function engineVectors()
    {
        // tests from http://csrc.nist.gov/publications/nistpubs/800-20/800-20.pdf#page=273
        $tests = array(
            // Table A.1
            // key, plaintext, ciphertext
            array(str_repeat("\x01", 24), pack('H*', '8000000000000000'), pack('H*', '95F8A5E5DD31D900')),
            array(str_repeat("\x01", 24), pack('H*', '4000000000000000'), pack('H*', 'DD7F121CA5015619')),
            array(str_repeat("\x01", 24), pack('H*', '2000000000000000'), pack('H*', '2E8653104F3834EA')),
            array(str_repeat("\x01", 24), pack('H*', '1000000000000000'), pack('H*', '4BD388FF6CD81D4F')),
            array(str_repeat("\x01", 24), pack('H*', '0800000000000000'), pack('H*', '20B9E767B2FB1456')),
            array(str_repeat("\x01", 24), pack('H*', '0400000000000000'), pack('H*', '55579380D77138EF')),
            array(str_repeat("\x01", 24), pack('H*', '0200000000000000'), pack('H*', '6CC5DEFAAF04512F')),
            array(str_repeat("\x01", 24), pack('H*', '0100000000000000'), pack('H*', '0D9F279BA5D87260')),
            array(str_repeat("\x01", 24), pack('H*', '0080000000000000'), pack('H*', 'D9031B0271BD5A0A')),
            array(str_repeat("\x01", 24), pack('H*', '0040000000000000'), pack('H*', '424250B37C3DD951')),
            array(str_repeat("\x01", 24), pack('H*', '0020000000000000'), pack('H*', 'B8061B7ECD9A21E5')),
            array(str_repeat("\x01", 24), pack('H*', '0010000000000000'), pack('H*', 'F15D0F286B65BD28')),
            array(str_repeat("\x01", 24), pack('H*', '0008000000000000'), pack('H*', 'ADD0CC8D6E5DEBA1')),
            array(str_repeat("\x01", 24), pack('H*', '0004000000000000'), pack('H*', 'E6D5F82752AD63D1')),
            array(str_repeat("\x01", 24), pack('H*', '0002000000000000'), pack('H*', 'ECBFE3BD3F591A5E')),
            array(str_repeat("\x01", 24), pack('H*', '0001000000000000'), pack('H*', 'F356834379D165CD')),
            array(str_repeat("\x01", 24), pack('H*', '0000800000000000'), pack('H*', '2B9F982F20037FA9')),
            array(str_repeat("\x01", 24), pack('H*', '0000400000000000'), pack('H*', '889DE068A16F0BE6')),
            array(str_repeat("\x01", 24), pack('H*', '0000200000000000'), pack('H*', 'E19E275D846A1298')),
            array(str_repeat("\x01", 24), pack('H*', '0000100000000000'), pack('H*', '329A8ED523D71AEC')),
            array(str_repeat("\x01", 24), pack('H*', '0000080000000000'), pack('H*', 'E7FCE22557D23C97')),
            array(str_repeat("\x01", 24), pack('H*', '0000040000000000'), pack('H*', '12A9F5817FF2D65D')),
            array(str_repeat("\x01", 24), pack('H*', '0000020000000000'), pack('H*', 'A484C3AD38DC9C19')),
            array(str_repeat("\x01", 24), pack('H*', '0000010000000000'), pack('H*', 'FBE00A8A1EF8AD72')),
            array(str_repeat("\x01", 24), pack('H*', '0000008000000000'), pack('H*', '750D079407521363')),
            array(str_repeat("\x01", 24), pack('H*', '0000004000000000'), pack('H*', '64FEED9C724C2FAF')),
            array(str_repeat("\x01", 24), pack('H*', '0000002000000000'), pack('H*', 'F02B263B328E2B60')),
            array(str_repeat("\x01", 24), pack('H*', '0000001000000000'), pack('H*', '9D64555A9A10B852')),
            array(str_repeat("\x01", 24), pack('H*', '0000000800000000'), pack('H*', 'D106FF0BED5255D7')),
            array(str_repeat("\x01", 24), pack('H*', '0000000400000000'), pack('H*', 'E1652C6B138C64A5')),
            array(str_repeat("\x01", 24), pack('H*', '0000000200000000'), pack('H*', 'E428581186EC8F46')),
            array(str_repeat("\x01", 24), pack('H*', '0000000100000000'), pack('H*', 'AEB5F5EDE22D1A36')),
            array(str_repeat("\x01", 24), pack('H*', '0000000080000000'), pack('H*', 'E943D7568AEC0C5C')),
            array(str_repeat("\x01", 24), pack('H*', '0000000040000000'), pack('H*', 'DF98C8276F54B04B')),
            array(str_repeat("\x01", 24), pack('H*', '0000000020000000'), pack('H*', 'B160E4680F6C696F')),
            array(str_repeat("\x01", 24), pack('H*', '0000000010000000'), pack('H*', 'FA0752B07D9C4AB8')),
            array(str_repeat("\x01", 24), pack('H*', '0000000008000000'), pack('H*', 'CA3A2B036DBC8502')),
            array(str_repeat("\x01", 24), pack('H*', '0000000004000000'), pack('H*', '5E0905517BB59BCF')),
            array(str_repeat("\x01", 24), pack('H*', '0000000002000000'), pack('H*', '814EEB3B91D90726')),
            array(str_repeat("\x01", 24), pack('H*', '0000000001000000'), pack('H*', '4D49DB1532919C9F')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000800000'), pack('H*', '25EB5FC3F8CF0621')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000400000'), pack('H*', 'AB6A20C0620D1C6F')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000200000'), pack('H*', '79E90DBC98F92CCA')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000100000'), pack('H*', '866ECEDD8072BB0E')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000080000'), pack('H*', '8B54536F2F3E64A8')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000040000'), pack('H*', 'EA51D3975595B86B')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000020000'), pack('H*', 'CAFFC6AC4542DE31')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000010000'), pack('H*', '8DD45A2DDF90796C')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000008000'), pack('H*', '1029D55E880EC2D0')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000004000'), pack('H*', '5D86CB23639DBEA9')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000002000'), pack('H*', '1D1CA853AE7C0C5F')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000001000'), pack('H*', 'CE332329248F3228')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000000800'), pack('H*', '8405D1ABE24FB942')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000000400'), pack('H*', 'E643D78090CA4207')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000000200'), pack('H*', '48221B9937748A23')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000000100'), pack('H*', 'DD7C0BBD61FAFD54')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000000080'), pack('H*', '2FBC291A570DB5C4')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000000040'), pack('H*', 'E07C30D7E4E26E12')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000000020'), pack('H*', '0953E2258E8E90A1')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000000010'), pack('H*', '5B711BC4CEEBF2EE')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000000008'), pack('H*', 'CC083F1E6D9E85F6')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000000004'), pack('H*', 'D2FD8867D50D2DFE')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000000002'), pack('H*', '06E7EA22CE92708F')),
            array(str_repeat("\x01", 24), pack('H*', '0000000000000001'), pack('H*', '166B40B44ABA4BD6'))
        );
        $result = array();
        // @codingStandardsIgnoreStart
        foreach ($this->engines as $engine => $engineName) 
        foreach ($tests as $test)
            $result[] = array($engine, $engineName, $test[0], $test[1], $test[2]);
        // @codingStandardsIgnoreEnd
        return $result;
    }

    /**
    * @dataProvider engineVectors
    */
    public function testVectors($engine, $engineName, $key, $plaintext, $expected)
    {
        $des = new TripleDES();
        if (!$des->isValidEngine($engine)) {
            self::markTestSkipped('Unable to initialize ' . $engineName . ' engine');
        }
        $des->setPreferredEngine($engine);
        $des->setKey($key);
        $des->disablePadding();
        $result = $des->encrypt($plaintext);
        $plaintext = bin2hex($plaintext);
        $this->assertEquals($result, $expected, "Failed asserting that $plaintext yielded expected output in $engineName engine");
    }

    public function engineIVVectors()
    {
        $engines = array(
            Base::ENGINE_INTERNAL => 'internal',
            Base::ENGINE_MCRYPT => 'mcrypt',
            Base::ENGINE_OPENSSL => 'OpenSSL',
        );

        // tests from http://csrc.nist.gov/groups/STM/cavp/documents/des/DESMMT.pdf
        $tests = array(
            // key, iv, plaintext, ciphertext
            array(
                pack('H*', '627f460e08104a10' . '43cd265d5840eaf1' . '313edf97df2a8a8c'),
                pack('H*', '8e29f75ea77e5475'),
                pack('H*', '326a494cd33fe756'),
                pack('H*', 'b22b8d66de970692')),
            array(
                pack('H*', '37ae5ebf46dff2dc' . '0754b94f31cbb385' . '5e7fd36dc870bfae'),
                pack('H*', '3d1de3cc132e3b65'),
                pack('H*', '84401f78fe6c10876d8ea23094ea5309'),
                pack('H*', '7b1f7c7e3b1c948ebd04a75ffba7d2f5'))
        );
        $result = array();
        // @codingStandardsIgnoreStart
        foreach ($engines as $engine => $engineName) 
        foreach ($tests as $test)
            $result[] = array($engine, $engineName, $test[0], $test[1], $test[2], $test[3]);
        // @codingStandardsIgnoreEnd
        return $result;
    }

    /**
    * @dataProvider engineIVVectors
    */
    public function testVectorsWithIV($engine, $engineName, $key, $iv, $plaintext, $expected)
    {
        $des = new TripleDES();
        if (!$des->isValidEngine($engine)) {
            self::markTestSkipped('Unable to initialize ' . $engineName . ' engine');
        }
        $des->setPreferredEngine($engine);
        $des->setKey($key);
        $des->setIV($iv);
        $des->disablePadding();
        $result = $des->encrypt($plaintext);
        $plaintext = bin2hex($plaintext);
        $this->assertEquals($result, $expected, "Failed asserting that $plaintext yielded expected output in $engineName engine");
    }

    public function testInnerChaining()
    {
        // regular CBC returns
        //           e089b6d84708c6bc80be6c2da82bd19a79ffe11f02933ac1
        $expected = 'e089b6d84708c6bc6f04c8971121603d7be2861efae0f3f5';

        $des = new TripleDES(TripleDES::MODE_3CBC);
        $des->setKey('abcdefghijklmnopqrstuvwx');

        foreach ($this->engines as $engine => $engineName) {
            $des->setPreferredEngine($engine);
            if (!$des->isValidEngine($engine)) {
                self::markTestSkipped('Unable to initialize ' . $engineName . ' engine');
            }
            $result = bin2hex($des->encrypt(str_repeat('a', 16)));
            $this->assertEquals($result, $expected, "Failed asserting inner chainin worked correctly in $engineName engine");
        }
    }
}
