<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'Crypt/RC4.php';

class Unit_Crypt_RC4_TestCase extends PhpseclibTestCase
{
    public function engineVectors()
    {
        $engines = array(
            'CRYPT_ENGINE_INTERNAL' => 'internal',
            'CRYPT_ENGINE_MCRYPT' => 'mcrypt',
            'CRYPT_ENGINE_OPENSSL' => 'OpenSSL',
        );
        // tests from https://tools.ietf.org/html/rfc6229
        $tests = array(
            array(
                'key' => pack('H*', '0102030405'),
                'output' => array(
                    array('offset' =>    0, 'result' => 'b2396305f03dc027ccc3524a0a1118a8'),
                    array('offset' =>   16, 'result' => '6982944f18fc82d589c403a47a0d0919'),
                    array('offset' =>  240, 'result' => '28cb1132c96ce286421dcaadb8b69eae'),
                    array('offset' =>  256, 'result' => '1cfcf62b03eddb641d77dfcf7f8d8c93'),
                    array('offset' =>  496, 'result' => '42b7d0cdd918a8a33dd51781c81f4041'),
                    array('offset' =>  512, 'result' => '6459844432a7da923cfb3eb4980661f6'),
                    array('offset' =>  752, 'result' => 'ec10327bde2beefd18f9277680457e22'),
                    array('offset' =>  768, 'result' => 'eb62638d4f0ba1fe9fca20e05bf8ff2b'),
                    array('offset' => 1008, 'result' => '45129048e6a0ed0b56b490338f078da5'),
                    array('offset' => 1024, 'result' => '30abbcc7c20b01609f23ee2d5f6bb7df'),
                    array('offset' => 1520, 'result' => '3294f744d8f9790507e70f62e5bbceea'),
                    array('offset' => 1536, 'result' => 'd8729db41882259bee4f825325f5a130'),
                    array('offset' => 2032, 'result' => '1eb14a0c13b3bf47fa2a0ba93ad45b8b'),
                    array('offset' => 2048, 'result' => 'cc582f8ba9f265e2b1be9112e975d2d7'),
                    array('offset' => 3056, 'result' => 'f2e30f9bd102ecbf75aaade9bc35c43c'),
                    array('offset' => 3072, 'result' => 'ec0e11c479dc329dc8da7968fe965681'),
                    array('offset' => 4080, 'result' => '068326a2118416d21f9d04b2cd1ca050'),
                    array('offset' => 4096, 'result' => 'ff25b58995996707e51fbdf08b34d875')
                )
            ),
            array(
                'key' => pack('H*', '01020304050607'),
                'output' => array(
                    array('offset' =>    0, 'result' => '293f02d47f37c9b633f2af5285feb46b'),
                    array('offset' =>   16, 'result' => 'e620f1390d19bd84e2e0fd752031afc1'),
                    array('offset' =>  240, 'result' => '914f02531c9218810df60f67e338154c'),
                    array('offset' =>  256, 'result' => 'd0fdb583073ce85ab83917740ec011d5'),
                    array('offset' =>  496, 'result' => '75f81411e871cffa70b90c74c592e454'),
                    array('offset' =>  512, 'result' => '0bb87202938dad609e87a5a1b079e5e4'),
                    array('offset' =>  752, 'result' => 'c2911246b612e7e7b903dfeda1dad866'),
                    array('offset' =>  768, 'result' => '32828f91502b6291368de8081de36fc2'),
                    array('offset' => 1008, 'result' => 'f3b9a7e3b297bf9ad804512f9063eff1'),
                    array('offset' => 1024, 'result' => '8ecb67a9ba1f55a5a067e2b026a3676f'),
                    array('offset' => 1520, 'result' => 'd2aa902bd42d0d7cfd340cd45810529f'),
                    array('offset' => 1536, 'result' => '78b272c96e42eab4c60bd914e39d06e3'),
                    array('offset' => 2032, 'result' => 'f4332fd31a079396ee3cee3f2a4ff049'),
                    array('offset' => 2048, 'result' => '05459781d41fda7f30c1be7e1246c623'),
                    array('offset' => 3056, 'result' => 'adfd3868b8e51485d5e610017e3dd609'),
                    array('offset' => 3072, 'result' => 'ad26581c0c5be45f4cea01db2f3805d5'),
                    array('offset' => 4080, 'result' => 'f3172ceffc3b3d997c85ccd5af1a950c'),
                    array('offset' => 4096, 'result' => 'e74b0b9731227fd37c0ec08a47ddd8b8')
                )
            ),
            array(
                'key' => pack('H*', '0102030405060708'),
                'output' => array(
                    array('offset' =>    0, 'result' => '97ab8a1bf0afb96132f2f67258da15a8'),
                    array('offset' =>   16, 'result' => '8263efdb45c4a18684ef87e6b19e5b09'),
                    array('offset' =>  240, 'result' => '9636ebc9841926f4f7d1f362bddf6e18'),
                    array('offset' =>  256, 'result' => 'd0a990ff2c05fef5b90373c9ff4b870a'),
                    array('offset' =>  496, 'result' => '73239f1db7f41d80b643c0c52518ec63'),
                    array('offset' =>  512, 'result' => '163b319923a6bdb4527c626126703c0f'),
                    array('offset' =>  752, 'result' => '49d6c8af0f97144a87df21d91472f966'),
                    array('offset' =>  768, 'result' => '44173a103b6616c5d5ad1cee40c863d0'),
                    array('offset' => 1008, 'result' => '273c9c4b27f322e4e716ef53a47de7a4'),
                    array('offset' => 1024, 'result' => 'c6d0e7b226259fa9023490b26167ad1d'),
                    array('offset' => 1520, 'result' => '1fe8986713f07c3d9ae1c163ff8cf9d3'),
                    array('offset' => 1536, 'result' => '8369e1a965610be887fbd0c79162aafb'),
                    array('offset' => 2032, 'result' => '0a0127abb44484b9fbef5abcae1b579f'),
                    array('offset' => 2048, 'result' => 'c2cdadc6402e8ee866e1f37bdb47e42c'),
                    array('offset' => 3056, 'result' => '26b51ea37df8e1d6f76fc3b66a7429b3'),
                    array('offset' => 3072, 'result' => 'bc7683205d4f443dc1f29dda3315c87b'),
                    array('offset' => 4080, 'result' => 'd5fa5a3469d29aaaf83d23589db8c85b'),
                    array('offset' => 4096, 'result' => '3fb46e2c8f0f068edce8cdcd7dfc5862')
                )
            )
        );
        $result = array();
        // @codingStandardsIgnoreStart
        foreach ($engines as $engine => $engineName)
        foreach ($tests as $test)
        foreach ($test['output'] as $output)
            $result[] = array($engine, $engineName, $test['key'], $output['offset'], $output['result']);
        // @codingStandardsIgnoreEnd
        return $result;
    }

    /**
    * @dataProvider engineVectors
    */
    public function testVectors($engine, $engineName, $key, $offset, $expected)
    {
        $rc4 = new Crypt_RC4();
        $rc4->setPreferredEngine($engine);
        if ($rc4->getEngine() != $engine) {
            self::markTestSkipped('Unable to initialize ' . $engineName . ' engine');
        }
        $rc4->setKey(pack('H*', $key));
        $result = $rc4->encrypt(str_repeat("\0", $offset + 16));
        $this->assertEquals(bin2hex(substr($result, -16)), $expected, "Failed asserting that key $key yielded expected output at offset $offset in $engineName engine");
    }
}
