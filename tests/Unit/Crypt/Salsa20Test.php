<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib3\Crypt\Salsa20;

class Unit_Crypt_Salsa20Test extends PhpseclibTestCase
{
    public function engineVectors()
    {
        $engines = [
            'PHP',
        ];
        // tests from http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/salsa20/full/verified.test-vectors?logsort=rev&rev=210&view=markup
        // more specifically, it's vector # 0 in each set
        $tests = [
            // key size: 128 bits
            // set 1
            [
                'key' => '80000000000000000000000000000000',
                'iv' => '0000000000000000',
                'result' => 'F7A274D268316790A67EC058F45C0F2A' .
                            '067A99FCDE6236C0CEF8E056349FE54C' .
                            '5F13AC74D2539570FD34FEAB06C57205' .
                            '3949B59585742181A5A760223AFA22D4'
            ],
            // set 2
            [
                'key' => '00000000000000000000000000000000',
                'iv' => '0000000000000000',
                'result' => '6D3937FFA13637648E477623277644AD' .
                            'AD3854E6B2B3E4D68155356F68B30490' .
                            '842B2AEA2E32239BE84E613C6CE1B9BD' .
                            '026094962CB1A6757AF5A13DDAF8252C'
            ],
            // set 3
            [
                'key' => '000102030405060708090A0B0C0D0E0F',
                'iv' => '0000000000000000',
                'result' => 'F3BCF4D6381742839C5627050D4B227F' .
                            'EB1ECCC527BF605C4CB9D6FB0618F419' .
                            'B51846707550BBEEE381E44A50A406D0' .
                            '20C8433D08B19C98EFC867ED9897EDBB'
            ],
            // set 4
            [
                'key' => '0053A6F94C9FF24598EB3E91E4378ADD',
                'iv' => '0000000000000000',
                'result' => '196D1A0977F0585B23367497D449E11D' .
                            'E328ECD944BC133F786348C9591B35B7' .
                            '189CDDD934757ED8F18FBC984DA377A8' .
                            '07147F1A6A9A8759FD2A062FD76D275E'
            ],
            // set 5
            [
                'key' => '00000000000000000000000000000000',
                'iv' => '8000000000000000',
                'result' => '104639D9F65C879F7DFF8A82A94C130C' .
                            'D6C727B3BC8127943ACDF0AB7AD6D28B' .
                            'F2ADF50D81F50C53D0FDFE15803854C7' .
                            'D67F6C9B4752275696E370A467A4C1F8'
            ],
            // set 6
            [
                'key' => '0053A6F94C9FF24598EB3E91E4378ADD',
                'iv' => '0D74DB42A91077DE',
                'result' => '620BB4C2ED20F4152F0F86053D3F5595' .
                            '8E1FBA48F5D86B25C8F31559F3158072' .
                            '6E7ED8525D0B9EA5264BF97750713476' .
                            '1EF65FE195274AFBF000938C03BA59A7'
            ],
            // key size: 256 bits
            // set 1
            [
                'key' => '8000000000000000000000000000000000000000000000000000000000000000',
                'iv' => '0000000000000000',
                'result' => '50EC2485637DB19C6E795E9C73938280' .
                            '6F6DB320FE3D0444D56707D7B456457F' .
                            '3DB3E8D7065AF375A225A70951C8AB74' .
                            '4EC4D595E85225F08E2BC03FE1C42567'
            ],
            // set 2
            [
                'key' => '0000000000000000000000000000000000000000000000000000000000000000',
                'iv' => '0000000000000000',
                'result' => '7C3A1499A63B507B0BC75824ABEEAA26' .
                            '109101C5B915F0F554DD9950045D02FA' .
                            'FF815CA8B2C7CFF3625765697B80B026' .
                            '7EA87E25412564BD71DD05843A60465E'
            ],
            // set 3
            [
                'key' => '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
                'iv' => '0000000000000000',
                'result' => '8C03E9237FEE95D5041C753C204D2B35' .
                            '764E4A53035A76F9EFBADD7E63E60B69' .
                            'BF23F7C5FD39B2249B0C628FB654D521' .
                            '4EB588371E5D2F34BF51396AF3ACB666'
            ],
            // set 4
            [
                'key' => '0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D',
                'iv' => '0000000000000000',
                'result' => '2052F9A2853E989133D10938222AC76D' .
                            'B8B4CBA135ACB59970DDF9C074C6271A' .
                            '5C4E2A7A00D2D697EDFC9B1FF9B365C8' .
                            '7347B23020663A30711A71E3A02AB00C'
            ],
            // set 5
            [
                'key' => '0000000000000000000000000000000000000000000000000000000000000000',
                'iv' => '8000000000000000',
                'result' => 'FE40F57D1586D7664C2FCA5AB10BD7C7' .
                            '9DE3234836E76949F9DC01CBFABC6D6C' .
                            '42AB27DDC748B4DF7991092972AB4985' .
                            'CEC19B3E7C2C85D6E25A338DEC288282'
            ],
            // set 6
            [
                'key' => '0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D',
                'iv' => '0D74DB42A91077DE',
                'result' => 'C349B6A51A3EC9B712EAED3F90D8BCEE' .
                            '69B7628645F251A996F55260C62EF31F' .
                            'D6C6B0AEA94E136C9D984AD2DF3578F7' .
                            '8E457527B03A0450580DD874F63B1AB9'
            ],
        ];

        $result = [];

        foreach ($engines as $engine) {
            foreach ($tests as $test) {
                $result[] = [$engine, $test['key'], $test['iv'], $test['result']];
            }
        }

        return $result;
    }

    /**
     * @dataProvider engineVectors
     */
    public function testVectors($engine, $key, $iv, $expected)
    {
        $cipher = new Salsa20();
        $cipher->setPreferredEngine($engine);
        $cipher->setKey(pack('H*', $key));
        $cipher->setNonce(pack('H*', $iv));
        if ($cipher->getEngine() != $engine) {
            self::markTestSkipped('Unable to initialize ' . $engine . ' engine for ' . (strlen($key) * 8) . '-bit key');
        }
        $result = $cipher->encrypt(str_repeat("\0", 64));
        $this->assertEquals(bin2hex($result), $expected, "Failed asserting that key $key / $iv yielded expected output in $engine engine");
    }
}
