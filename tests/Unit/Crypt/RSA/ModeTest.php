<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2013 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;

class Unit_Crypt_RSA_ModeTest extends PhpseclibTestCase
{
    public function testEncryptionModeNone()
    {
        $plaintext = 'a';

        $rsa = new RSA();

        $privatekey = '-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=
-----END RSA PRIVATE KEY-----';
        $rsa->load($privatekey);
        $rsa->load($rsa->getPublicKey());

        $expected = '105b92f59a87a8ad4da52c128b8c99491790ef5a54770119e0819060032fb9e772ed6772828329567f3d7e9472154c1530f8156ba7fd732f52ca1c06' .
            '5a3f5ed8a96c442e4662e0464c97f133aed31262170201993085a589565d67cc9e727e0d087e3b225c8965203b271e38a499c92fc0d6502297eca712' .
            '4d04bd467f6f1e7c';
        $expected = pack('H*', $expected);
        $result = $rsa->encrypt($plaintext, RSA::PADDING_NONE);

        $this->assertEquals($result, $expected);

        $rsa->load($privatekey);
        $this->assertEquals(trim($rsa->decrypt($result, RSA::PADDING_NONE), "\0"), $plaintext);
    }

    /**
     * @group github768
     */
    public function testPSSSigs()
    {
        $rsa = new RSA();
        $rsa->setHash('sha1');
        $rsa->setMGFHash('sha1');
        $rsa->load('-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVx
wTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFnc
CzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0T
p0GbMJDyR4e9T04ZZwIDAQAB
-----END PUBLIC KEY-----');

        $sig = pack('H*', '1bd29a1d704a906cd7f726370ce1c63d8fb7b9a620871a05f3141a311c0d6e75fefb5d36dfb50d3ea2d37cd67992471419bfadd35da6e13b494' .
            '058ddc9b568d4cfea13ddc3c62b86a6256f5f296980d1131d3eaec6089069a3de79983f73eae20198a18721338b4a66e9cfe80e4f8e4fcef7a5bead5cbb' .
            'b8ac4c76adffbc178c');

        $this->assertTrue($rsa->verify('zzzz', $sig));
    }

    /**
     * @expectedException \LengthException
     */
    public function testSmallModulo()
    {
        $plaintext = 'x';
        $n = new BigInteger(base64_decode('272435F22706FA96DE26E980D22DFF67'), 256);
        $e = new BigInteger(base64_decode('158753FF2AF4D1E5BBAB574D5AE6B54D'), 256);

        $rsa = new RSA();
        $rsa->load(array('n' => $n, 'e' => $e));
        $rsa->encrypt($plaintext);
    }

    public function testPKCS1LooseVerify()
    {
        $rsa = new RSA();
        $rsa->load('-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMuqkz8ij+ESAaNvgocVGmapjlrIldmhRo4h2NX4e6IXiCLTSxASQtY4
iqRnmyxqQSfaan2okTfQ6sP95bl8Qz8lgneW3ClC6RXG/wpJgsx7TXQ2kodlcKBF
m4k72G75QXhZ+I40ZG7cjBf1/9egakR0a0X0MpeOrKCzMBLv9+mpAgMBAAE=
-----END RSA PUBLIC KEY-----');

        $message = base64_decode('MYIBLjAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNDA1MTUxNDM4MzRaMC8GCSqGSIb3DQEJBDEiBCBLzLIBGdOf0L2WRrIY' .
            '9KTwiHnReBW48S9C7LNRaPp5mDCBwgYLKoZIhvcNAQkQAi8xgbIwga8wgawwgakEIJDB9ZGwihf+TaiwrHQNkNHkqbN8Nuws0e77QNObkvFZMIGEMHCkbjBs' .
            'MQswCQYDVQQGEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eUMxIDAeBgNVBAMMF0FydWJh' .
            'UEVDIFMucC5BLiBORyBDQSAzAhAv4L3QcFssQNLDYN/Vu40R');

        $sig = base64_decode('XDSZWw6IcUj8ICxRJf04HzF8stzoiFAZSR2a0Rw3ziZxTOT0/NVUYJO5+9TaaREXEgxuCLpgmA+6W2SWrrGoxbbNfaI90ZoKeOAws4IX+9RfiWuooibjKcvt' .
            'GJYVVOCcjvQYxUUNbQ4EjCUonk3h7ECXfCCmWqbeq2LsyXeeYGE=');

        $this->assertTrue($rsa->verify($message, $sig, RSA::PADDING_RELAXED_PKCS1));
    }
}
