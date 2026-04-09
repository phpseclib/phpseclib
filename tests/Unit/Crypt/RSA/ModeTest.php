<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2013 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\RSA;

use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Crypt\RSA;
use phpseclib4\Crypt\RSA\Formats\Keys\PKCS8;
use phpseclib4\Exception\BadConfigurationException;
use phpseclib4\Math\BigInteger;
use phpseclib4\Tests\PhpseclibTestCase;

class ModeTest extends PhpseclibTestCase
{
    public function testEncryptionModeNone(): void
    {
        $plaintext = 'a';

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

        // libsodium doesn't support RSA but it still ought not result in any errors outside of the BadConfigurationException being thrown
        $engines = ['libsodium', 'OpenSSL', 'PHP'];
        foreach ($engines as $engine) {
            try {
                RSA::forceEngine($engine);
                $rsa = PublicKeyLoader::load($privatekey);
                $rsa = $rsa->getPublicKey()
                    ->withPadding(RSA::ENCRYPTION_NONE);

                $expected = '105b92f59a87a8ad4da52c128b8c99491790ef5a54770119e0819060032fb9e772ed6772828329567f3d7e9472154c1530f8156ba7fd732f52ca1c06' .
                    '5a3f5ed8a96c442e4662e0464c97f133aed31262170201993085a589565d67cc9e727e0d087e3b225c8965203b271e38a499c92fc0d6502297eca712' .
                    '4d04bd467f6f1e7c';
                $expected = pack('H*', $expected);
                $result = $rsa->encrypt($plaintext);

                $this->assertEquals($result, $expected);

                $rsa = PublicKeyLoader::load($privatekey)
                    ->withPadding(RSA::ENCRYPTION_NONE);
                $this->assertEquals(trim($rsa->decrypt($result), "\0"), $plaintext);
            } catch (BadConfigurationException $e) {
            }
        }
        // reset
        RSA::forceEngine();
    }

    /**
     * @group github768
     */
    public function testPSSSigs(): void
    {
        $rsa = PublicKeyLoader::load('-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVx
wTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFnc
CzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0T
p0GbMJDyR4e9T04ZZwIDAQAB
-----END PUBLIC KEY-----')
            ->withHash('sha1')
            ->withMGFHash('sha1');

        $sig = pack('H*', '1bd29a1d704a906cd7f726370ce1c63d8fb7b9a620871a05f3141a311c0d6e75fefb5d36dfb50d3ea2d37cd67992471419bfadd35da6e13b494' .
            '058ddc9b568d4cfea13ddc3c62b86a6256f5f296980d1131d3eaec6089069a3de79983f73eae20198a18721338b4a66e9cfe80e4f8e4fcef7a5bead5cbb' .
            'b8ac4c76adffbc178c');

        $engines = ['libsodium', 'OpenSSL', 'PHP'];
        foreach ($engines as $engine) {
            try {
                RSA::forceEngine($engine);
                $this->assertTrue($rsa->verify('zzzz', $sig));
            } catch (BadConfigurationException $e) {
            }
        }
        // reset
        RSA::forceEngine();
    }

    public function testSmallModulo(): void
    {
        $this->expectException('LengthException');

        $plaintext = 'x';

        $key = PKCS8::savePublicKey(
            new BigInteger(base64_decode('272435F22706FA96DE26E980D22DFF67'), 256), // n
            new BigInteger(base64_decode('158753FF2AF4D1E5BBAB574D5AE6B54D'), 256)  // e
        );
        $rsa = PublicKeyLoader::load($key);

        $engines = ['libsodium', 'OpenSSL', 'PHP'];
        foreach ($engines as $engine) {
            try {
                RSA::forceEngine($engine);
                $rsa->encrypt($plaintext);
                 // libsodium and OpenSSL should both return BadConfigurationException's - only the PHP engine should
                 // throw a LengthException
            } catch (BadConfigurationException $e) {
            }
        }
        // reset
        RSA::forceEngine();
    }

    public function testPKCS1LooseVerify(): void
    {
        $rsa = PublicKeyLoader::load('-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMuqkz8ij+ESAaNvgocVGmapjlrIldmhRo4h2NX4e6IXiCLTSxASQtY4
iqRnmyxqQSfaan2okTfQ6sP95bl8Qz8lgneW3ClC6RXG/wpJgsx7TXQ2kodlcKBF
m4k72G75QXhZ+I40ZG7cjBf1/9egakR0a0X0MpeOrKCzMBLv9+mpAgMBAAE=
-----END RSA PUBLIC KEY-----')
            ->withPadding(RSA::SIGNATURE_RELAXED_PKCS1);

        $message = base64_decode('MYIBLjAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNDA1MTUxNDM4MzRaMC8GCSqGSIb3DQEJBDEiBCBLzLIBGdOf0L2WRrIY' .
            '9KTwiHnReBW48S9C7LNRaPp5mDCBwgYLKoZIhvcNAQkQAi8xgbIwga8wgawwgakEIJDB9ZGwihf+TaiwrHQNkNHkqbN8Nuws0e77QNObkvFZMIGEMHCkbjBs' .
            'MQswCQYDVQQGEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eUMxIDAeBgNVBAMMF0FydWJh' .
            'UEVDIFMucC5BLiBORyBDQSAzAhAv4L3QcFssQNLDYN/Vu40R');

        $sig = base64_decode('XDSZWw6IcUj8ICxRJf04HzF8stzoiFAZSR2a0Rw3ziZxTOT0/NVUYJO5+9TaaREXEgxuCLpgmA+6W2SWrrGoxbbNfaI90ZoKeOAws4IX+9RfiWuooibjKcvt' .
            'GJYVVOCcjvQYxUUNbQ4EjCUonk3h7ECXfCCmWqbeq2LsyXeeYGE=');

        $engines = ['libsodium', 'OpenSSL', 'PHP'];
        foreach ($engines as $engine) {
            try {
                RSA::forceEngine($engine);
                $this->assertTrue($rsa->verify($message, $sig));
                 // libsodium and OpenSSL should both return BadConfigurationException's - only the PHP engine should
                 // actually verify this
            } catch (BadConfigurationException $e) {
            }
        }
        // reset
        RSA::forceEngine();
    }

    public function testZeroLengthSalt(): void
    {
        $plaintext = 'a';

        $rsa = PublicKeyLoader::load('-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----')
            ->withSaltLength(0)
            ->withHash('sha1')
            ->withMGFHash('sha1');

        $engines = ['libsodium', 'OpenSSL', 'PHP'];
        foreach ($engines as $engine) {
            try {
                RSA::forceEngine($engine);

                // Check we generate the correct signature.
                $sig = pack('H*', '0ddfc93548e21d015c0a289a640b3b79aecfdfae045f583c5925b91cc5c399bba181616ad6ae20d9662d966f0eb2fddb550f4733268e34d640f4c9dadcaf25b3c82c42130a5081c6ebad7883331c65b25b6a37ffa7c4233a468dae56180787e2718ed87c48d8d50b72f5850e4a40963b4f36710be250ecef6fe0bb91249261a3');
                $this->assertEquals($sig, $rsa->sign($plaintext));

                // Check we can verify the signature correctly.
                $rsa = $rsa->getPublicKey();
                $this->assertTrue($rsa->verify($plaintext, $sig));
            } catch (BadConfigurationException $e) {
            }
        }

        // reset
        RSA::forceEngine();
    }

    /**
     * @group github1423
     */
    public function testPSSSigsWithNonPowerOf2Key(): void
    {
        $pub = <<<HERE
            -----BEGIN PUBLIC KEY-----
            MF0wDQYJKoZIhvcNAQEBBQADTAAwSQJCAmdYuOvii3I6ya3q/zSeZFoJprgF9fIq
            k12yS6pCS3c+1wZ9cYFVtgfpSL4XpylLe9EnRT2GRVYCqUkR4AUeTuvnAgMBAAE=
            -----END PUBLIC KEY-----
            HERE;

        $rsa = PublicKeyLoader::load($pub)
            ->withHash('sha256')
            ->withSaltLength(32)
            ->withMGFHash('sha256');

        $sig = base64_decode(strtr('Ad022bD-UCmWpBNMtsYJjG0FVxML-FFlN4IKrByP8rwjVzV_D-YqSjc_oW6LrooV7jbtEF5803YLn8lllyzDnw00', '-_', '+/'));
        $payload = 'eyJraWQiOiJ0RkMyVUloRnBUTV9FYTNxY09kX01xUVQxY0JCbTlrRkxTRGZlSmhzUkc4IiwiYWxnIjoiUFMyNTYifQ.eyJhcHAiOiJhY2NvdW50cG9ydGFsIiwic3ViIjoiNTliOGM4YzA5NTVhNDA5MDg2MGRmYmM3ZGQwMjVjZWEiLCJjbGlkIjoiZTQ5ZTA2N2JiMTFjNDcyMmEzNGIyYjNiOGE2YTYzNTUiLCJhbSI6InBhc3N3b3JkIiwicCI6ImVOcDFrRUZQd3pBTWhmXC9QdEVOYU5kQkc2bUZDNHNpbENNNXU0aTNXMHFSS0hFVDU5V1JzcXpZRUp4XC84M3ZQbkIxcUg3Rm5CZVNabEtNME9saGVZVUVWTXlHOEVUOEZnWDI4dkdqWG4wWkcrV2hSK01rWVBicGZacHI2U3E0N0RFYjBLYkRFT21CSUZuOTZKN1ZDaWg1Q2p4dWNRZDJmdHJlMCt2cSthZFFObUluK0poWEl0UlBvQ0xya1wvZ05VV3N3T09vSVwva0Q5ZVk4c05jRHFPUzNkanFWb3RPU21oRUo5b0hZZmFqZmpSRzFGSWpGRFwvOExtT2pKbVF3d0tBMnQ0aXJBQ2NncHo0dzBuN3BtXC84YXV2T0dFM2twVFZ2d0IzdzlQZk1YZnJJUTBhejRsaEtIdVBUMU42XC9sb1FJPSIsImlhaSI6IjU5YjhjOGMwOTU1YTQwOTA4NjBkZmJjN2RkMDI1Y2VhIiwiY2xzdmMiOiJhY2NvdW50cG9ydGFsIiwibHB2IjoxNTQ3Njc1NDM4LCJ0IjoicyIsImljIjp0cnVlLCJleHAiOjE1NDc3MDQyMzgsImlhdCI6MTU0NzY3NTQzOCwianRpIjoiZTE0N2UzM2UzNzVhNDkyNWJjMzdjZTRjMDIwMmJjNDYifQ';

        $engines = ['libsodium', 'OpenSSL', 'PHP'];
        foreach ($engines as $engine) {
            try {
                RSA::forceEngine($engine);
                $this->assertTrue($rsa->verify($payload, $sig));
            } catch (BadConfigurationException $e) {
            }
        }
        // reset
        RSA::forceEngine();
    }

    public function testHash(): void
    {
        $pub = <<<HERE
            -----BEGIN PUBLIC KEY-----
            MF0wDQYJKoZIhvcNAQEBBQADTAAwSQJCAmdYuOvii3I6ya3q/zSeZFoJprgF9fIq
            k12yS6pCS3c+1wZ9cYFVtgfpSL4XpylLe9EnRT2GRVYCqUkR4AUeTuvnAgMBAAE=
            -----END PUBLIC KEY-----
            HERE;

        $rsa = PublicKeyLoader::load($pub)
            ->withHash('sha1')
            ->withSaltLength(5)
            ->withMGFHash('sha512');

        $this->assertEquals('sha1', $rsa->getHash());
        $this->assertSame(5, $rsa->getSaltLength());
        $this->assertEquals('sha512', $rsa->getMGFHash());

        $rsa = $rsa
            ->withHash('sha512')
            ->withSaltLength(6)
            ->withMGFHash('sha1');

        $this->assertEquals('sha512', $rsa->getHash());
        $this->assertSame(6, $rsa->getSaltLength());
        $this->assertEquals('sha1', $rsa->getMGFHash());
    }

    public function testPKCS1SigWithoutNull(): void
    {
        $rsa = PublicKeyLoader::load([
            'n' => new BigInteger(
                'E932AC92252F585B3A80A4DD76A897C8B7652952FE788F6EC8DD640587A1EE5647670A8AD' .
                '4C2BE0F9FA6E49C605ADF77B5174230AF7BD50E5D6D6D6D28CCF0A886A514CC72E51D209CC7' .
                '72A52EF419F6A953F3135929588EBE9B351FCA61CED78F346FE00DBB6306E5C2A4C6DFC3779' .
                'AF85AB417371CF34D8387B9B30AE46D7A5FF5A655B8D8455F1B94AE736989D60A6F2FD5CADB' .
                'FFBD504C5A756A2E6BB5CECC13BCA7503F6DF8B52ACE5C410997E98809DB4DC30D943DE4E81' .
                '2A47553DCE54844A78E36401D13F77DC650619FED88D8B3926E3D8E319C80C744779AC5D6AB' .
                'E252896950917476ECE5E8FC27D5F053D6018D91B502C4787558A002B9283DA7',
                16
            ),
            'e' => new BigInteger('3'),
        ]);

        $message = 'hello world!';
        $signature = pack('H*', 'a0073057133ff3758e7e111b4d7441f1d8cbe4b2dd5ee4316a14264290dee5ed7f175716639bd9bb43a14e4f9fcb9e84dedd35e2205caac04828b2c053f68176d971ea88534dd2eeec903043c3469fc69c206b2a8694fd262488441ed8852280c3d4994e9d42bd1d575c7024095f1a20665925c2175e089c0d731471f6cc145404edf5559fd2276e45e448086f71c78d0cc6628fad394a34e51e8c10bc39bfe09ed2f5f742cc68bee899d0a41e4c75b7b80afd1c321d89ccd9fe8197c44624d91cc935dfa48de3c201099b5b417be748aef29248527e8bbb173cab76b48478d4177b338fe1f1244e64d7d23f07add560d5ad50b68d6649a49d7bc3db686daaa7');

        $rsa = $rsa->withPadding(RSA::SIGNATURE_PKCS1);
        //$rsa = $rsa->withHash('sha256');

        $engines = ['libsodium', 'OpenSSL', 'PHP'];
        foreach ($engines as $engine) {
            try {
               RSA::forceEngine($engine);
               $this->assertTrue($rsa->verify($message, $signature));
            } catch (BadConfigurationException $e) {
            }
        }
        // reset
        RSA::forceEngine();
    }

    /**
     * @group github1669
     */
    public function testOAEPWithLabel(): void
    {
        $publicKey = PublicKeyLoader::load('-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnkFHQbt801+kMnxn0VmMVljp8
XdsbLEziLul3MwwckBDHwW6UDvYjN7vzJ/OM2RTxTbzilDcXJ37Zqz4qlDvXwSNm
gIe+3dpuuRQRrJuJP6FD8zDTkRmg3QWOIIPBTzCqOtJKgWjFwMMxfCOBFEv6Ldn5
Ac0i9ARl0/aNTWjvGwIDAQAB
-----END PUBLIC KEY-----');

        $privateKey = PublicKeyLoader::load('-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKeQUdBu3zTX6Qyf
GfRWYxWWOnxd2xssTOIu6XczDByQEMfBbpQO9iM3u/Mn84zZFPFNvOKUNxcnftmr
PiqUO9fBI2aAh77d2m65FBGsm4k/oUPzMNORGaDdBY4gg8FPMKo60kqBaMXAwzF8
I4EUS/ot2fkBzSL0BGXT9o1NaO8bAgMBAAECgYAO2OPW8ywF86ervaFAHDN1YzVV
db+HXdqGJB/9tuE42q8R9BrHNbgrkLGvrveOoGGRrBCzhuyGubIsuVat0SqoI6qE
nB9uahaIBfF5FZ7+bNW5OfkgerUUYP1S1MGFxUqINnUY1YHITmo6pUKHsiJtP7si
hnCT6uEx8LqVNf1quQJBANs+VCZVUDq6eMy3E/u03HiAB8cyqLVMVQ4cLyoiWmFl
nEFzZwMd20ZMjtcxICiizW3dlDvyxWYKH93irL0JyM0CQQDDp/VFsh83vKICVvM9
IZHwE/Z8vZA3eTkGbWmgnr6qaxqge3FU02kUvIHHlvLmXYIt30lTq0Rn+Lz+TGV/
jDeHAkBHYSaSiGojhLx5og1+gKbbEIv3vbWRuTVj76cnZ6HXXfaelIzwRdMzMw+6
XgMjV8XcRCzTy7ma/Cbd3cPxk/LtAkEAwkehMVexz/KrHI+icG1JMI9iDnNdJPhm
O4+hdzCqOyanBfwNiSF0Encslze4ci8f+NTjRwWlo2hGomzRzFk7OQJAPPd/o0az
kg9nF+JxLiz7hF+/6MLVZgIfw04u05ANtOSVVQP4UTmJ/tNAe3OBUQVlRQAJ1m3j
zUlir0ACPypC1Q==
-----END PRIVATE KEY-----');

        $data = 'The quick brown fox jumps over the lazy dog';

        $engines = ['libsodium', 'OpenSSL', 'PHP'];
        foreach ($engines as $engine) {
            try {
               RSA::forceEngine($engine);

                $ciphertext = $publicKey->withLabel('whatever')->encrypt($data);

                try {
                    $this->assertFalse($privateKey->decrypt($ciphertext));
                    $this->fail('Ciphertext should not have decrypted');
                } catch (\Exception $e) {
                }

                $decrypted = $privateKey->withLabel('whatever')->decrypt($ciphertext);

                $this->assertSame($data, $decrypted);
            } catch (BadConfigurationException $e) {
            }
        }
        // reset
        RSA::forceEngine();
    }

    public function testSettingOnePadding(): void
    {
        $pub = '-----BEGIN PUBLIC KEY-----
MF0wDQYJKoZIhvcNAQEBBQADTAAwSQJCAmdYuOvii3I6ya3q/zSeZFoJprgF9fIq
k12yS6pCS3c+1wZ9cYFVtgfpSL4XpylLe9EnRT2GRVYCqUkR4AUeTuvnAgMBAAE=
-----END PUBLIC KEY-----';

        $rsa = PublicKeyLoader::load($pub);
        $this->assertTrue((bool) ($rsa->getPadding() & RSA::SIGNATURE_PSS));
        $rsa = $rsa->withPadding(RSA::ENCRYPTION_NONE);
        $this->assertTrue((bool) ($rsa->getPadding() & RSA::SIGNATURE_PSS));
    }

    /**
     * @group github2132
     */
    public function testSHA3()
    {
        $key = PublicKeyLoader::load('-----BEGIN PUBLIC KEY-----
MIIDIjANBgkqhkiG9w0BAQEFAAOCAw8AMIIDCgKCAwEAlkcfflcUuP/wZRqsPlJT
zSOffEo6BkOsYZEEfUKT8M6EBTLoF6DsG6kbBYzAytlp7HeY6gO7PU6BuvzsotvT
Rf9bqKZQUVxyQssTOKE3eraS/HWpVyC0PVstieNds3jUI/b1MHSd4jWt02yl7nxO
VDOGD7er0Eq/o0uBsLGJCvD7dytiyKUUbyPuPxa3FyogHm9F6+8N2lCGPn5ST1cB
CE2QQZh+Wjjaf1OJPc3JhxPPPnJD3yMdAUC+FWE7i/fk/8k62EcJ4zWrPUGw4frC
Uf20tPsQ1Dd0telOWk9CwC1b9oXfSTDVjQlTBfjo11qaSBbqk/GK9UoHCkiq7PUa
Xw3vkUrPOt9tq/wDNlhi+YTumN6bjxc6HTmW/aM2gzxvswS0yX7IenKD8DPEgcpJ
yWWYUzE64FychCfdniZ+QZeiD+g1gdWbDn3p9fQ8S8eVu5TApIZQolWZal4q15Zg
NWxb6f1c05AAmquH5K4+7I4IDhlYLBfTEGVoSDM5gdYWORiFvGQb0Vv9awy0C8m1
8wN0z4l0qQsKCj/pR9WjoBCvAr2KGfY/S2p63tMpVFPOWFwOOmiWQQkpZ0TRCaZS
uOYBiFhKUnbSG83hfqeN9B9WNXou5HfJ+e/GAmYOxxXXTFTWtBHc85yT5rnmq6Pj
cz4aFnU7ZS7CaZtnCPkP4uctXicjJBNp+IDdB3hp4/Pqpaj+UeqbZadkcgEN7bWB
ogq3GblxZq6dBecX+XHWQx/3hBBIpmOnXZZHxlZCnhznGw6DBcFJ05gYf4p6nGyy
FED7HPhd43cbl2OZuP26u/np8EdnkJ0l4lbL2wtG+Xf9ySkKM1Lm7ZLdA510ADsd
ZJzqzE35adlcNcWyTeK9Aku9XuFPa4N1go46xkBnrK1LwE3XCDOr3ncbm3PCsic1
1U7AoljKI1EL4jvEa3P5y2UQlVBy+V5nL6QSmo88XeB30wKVcSLZfopjUUmIxrTx
dMHAqhC117qQfr2KEJPJnTnJjkuWpiW2gRuBSdVE20oNAgMBAAE=
-----END PUBLIC KEY-----');
        $sig = 'XPvvcjPAuUq1Ev7BAG63nh+KmXXbY6j0kzBKV2eYgzmuHHL5DmQJDKaHzg3qPkKznxokpQ1c5YG8p1X13vXfGzMFHQ2EHKGrfz8cGRFv8rxU9O8PH1liIqzOQQltcwBdZGdkHC/BY1v0AV9YT6zKZcGgkYgJG5gFLhGdTEr9c5+V98QeP1E27CUYFrhbN13xvkdMt67pIOrVdL4nVSC1XpMOrtDSydsVIR86xITWPbPngjzLwMXuBQ463rdCR0avcYTHUtxego9jVMAn2uAEWTZTMuearQZ/3rdtZejY0SDQbdmBdelGQkWMEOloIne3U5FfS+PPzVu+m64m1joYPbXDel/aZN+vrgkgB+lI2XxT100uji0TDHQ50HmOIxMELGeCXNo93vggMcTC5pmAgCBCIQPXlJFftNUHCqZ2v1set+QJpXsnaeRkRVElPthbuEupUW7Kq0VDqbFOam5M3yD4UAmDoLKkJGJ0uG1YVsqjrRM2EHx/yACmd92/kJcVWBPD4esBqKKkOylbEA1ljE+5EOSq95V1Z09w030WV2p8xh4lBHQHtbuUFLbq1YkZmn6jj7LrBOXEWzspARPNUyaI2xRs3E+Nik2N+Czg1uESsLlo/n+mP+A7Ygtt4bjuL80GT2T6yl8YM/jMmlF78nosWKbDrQI2LPjS/YaZOBI23D2DJJvXex/V9C5+/RgWzX5rl1zFYrPxKP2BKl53HMfR7NP5Rg20hOtdZedRYJtQTNWLfVUYSrXiggHBAgW+EnbxtqWjhtyUFZoIkaupI5DXvy/aJYBKLZaJ19MWeXmJkKMl5O6ADHi8q/Ca5sPah/bH3pn2UsDT0AqEWpTGVzktPhpDEPACqjiHz8mEnU/DNtPHigLytpJFFECkYa4FnC2eCOc8b4AfFl7F/qgCg+lMVLE3fMZ1NWT52w7TYb1DwaqMKWirTfwBF/368/eOCuIdVma3xmD3IMK+y43qZS3qTCR8YfOaIwxrS6T855kH0Cas73fx3eHq2ekwm18s';
        $sig = base64_decode($sig);
        $this->assertTrue($key->withHash('sha3/512')->withMGFHash('sha3/512')->verify('hello world', $sig));
    }
}
