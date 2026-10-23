<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\RSA;

use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Crypt\RSA;
use phpseclib4\Crypt\RSA\Formats\Keys\PKCS8;
use phpseclib4\Crypt\RSA\PrivateKey;
use phpseclib4\Crypt\RSA\PublicKey;
use phpseclib4\Exception\BadConfigurationException;
use phpseclib4\Exception\BadDecryptionException;
use phpseclib4\Exception\KeyConstraintException;
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
                $this->assertInstanceOf(PrivateKey::class, $rsa);
                $rsa = $rsa->getPublicKey()
                    ->withPadding(RSA::ENCRYPTION_NONE);

                $expected = '105b92f59a87a8ad4da52c128b8c99491790ef5a54770119e0819060032fb9e772ed6772828329567f3d7e9472154c1530f8156ba7fd732f52ca1c06' .
                    '5a3f5ed8a96c442e4662e0464c97f133aed31262170201993085a589565d67cc9e727e0d087e3b225c8965203b271e38a499c92fc0d6502297eca712' .
                    '4d04bd467f6f1e7c';
                $expected = pack('H*', $expected);
                $result = $rsa->encrypt($plaintext);

                $this->assertEquals($result, $expected);

                $rsa = PublicKeyLoader::load($privatekey);
                $this->assertInstanceOf(PrivateKey::class, $rsa);
                $rsa = $rsa->withPadding(RSA::ENCRYPTION_NONE);
                $this->assertEquals(trim($rsa->decrypt($result), "\0"), $plaintext);
            } catch (BadConfigurationException $e) {
            }
        }
        // reset
        RSA::forceEngine();
    }

    public function testOpenSSLDecryptWithPassphraseProtectedPrivateKey(): void
    {
        if (!function_exists('openssl_private_decrypt')) {
            $this->markTestSkipped('OpenSSL is not available');
        }

        $probePrivatekey = RSA::createKey(1024)->withPadding(RSA::ENCRYPTION_NONE);
        $probePublickey = $probePrivatekey->getPublicKey()->withPadding(RSA::ENCRYPTION_NONE);
        $probePlaintext = str_repeat("\0", ($probePrivatekey->getLength() >> 3) - 5) . 'probe';
        $probeCiphertext = $probePublickey->encrypt($probePlaintext);
        $probeOutput = '';

        set_error_handler(function () {
            return true;
        });

        try {
            $canOpenSSLDecrypt = openssl_private_decrypt(
                $probeCiphertext,
                $probeOutput,
                $probePrivatekey->toString('PKCS8'),
                OPENSSL_NO_PADDING
            );
        } finally {
            restore_error_handler();
        }

        if (!$canOpenSSLDecrypt || $probeOutput !== $probePlaintext) {
            $this->markTestSkipped('OpenSSL private decrypt is not supported by this PHP/OpenSSL build');
        }

        $privatekey = RSA::createKey(1024)->withPassword('password');
        $privatekey = PublicKeyLoader::load($privatekey->toString('PKCS8'), 'password');
        $this->assertInstanceOf(PrivateKey::class, $privatekey);
        $privatekey = $privatekey->withPadding(RSA::ENCRYPTION_NONE);
        $publickey = $privatekey->getPublicKey()
            ->withPadding(RSA::ENCRYPTION_NONE);

        $plaintext = str_repeat("\0", ($privatekey->getLength() >> 3) - 5) . 'hello';
        $ciphertext = $publickey->encrypt($plaintext);

        RSA::forceEngine('OpenSSL');
        set_error_handler(function ($errno, $errstr) {
            throw new \ErrorException($errstr, 0, $errno);
        });

        try {
            $this->assertSame($plaintext, $privatekey->decrypt($ciphertext));
        } finally {
            restore_error_handler();
            RSA::forceEngine();
        }
    }

    #[\PHPUnit\Framework\Attributes\Group('github768')]
    public function testPSSSigs(): void
    {
        $rsa = PublicKeyLoader::load('-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVx
wTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFnc
CzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0T
p0GbMJDyR4e9T04ZZwIDAQAB
-----END PUBLIC KEY-----');
        $this->assertInstanceOf(PublicKey::class, $rsa);
        $rsa = $rsa
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

    public function testPSSSignAndVerifyAcrossEngines(): void
    {
        $privatekey = RSA::createKey(1024)
            ->withHash('sha256')
            ->withMGFHash('sha256')
            ->withPadding(RSA::SIGNATURE_PSS);
        $publickey = $privatekey->getPublicKey();

        $message = 'zzzz';
        $signature = $privatekey->sign($message);

        RSA::forceEngine('PHP');
        try {
            $this->assertTrue($publickey->verify($message, $signature));
        } finally {
            RSA::forceEngine();
        }
    }

    public function testPSSSignWithForcedOpenSSLEngineFailsOnSmallKey(): void
    {
        if (!defined('OPENSSL_PKCS1_PSS_PADDING')) {
            $this->markTestSkipped('OPENSSL_PKCS1_PSS_PADDING is not defined (requires PHP >= 8.5)');
        }

        $privatekey = RSA::createKey(512)
            ->withHash('sha256')
            ->withMGFHash('sha256')
            ->withPadding(RSA::SIGNATURE_PSS);

        RSA::forceEngine('OpenSSL');
        try {
            $this->expectException(BadConfigurationException::class);
            $privatekey->sign('zzzz');
        } finally {
            RSA::forceEngine();
        }
    }

    public function testPSSSignWithForcedOpenSSLEngineFailsOnOldOpenSSL(): void
    {
        if (!defined('OPENSSL_PKCS1_PSS_PADDING')) {
            $this->markTestSkipped('OPENSSL_PKCS1_PSS_PADDING is not defined (requires PHP >= 8.5)');
        }
        if (OPENSSL_VERSION_NUMBER >= 0x30100000) {
            $this->markTestSkipped('OpenSSL >= 3.1.0 defaults to a spec-compliant PSS salt length for this key size');
        }

        $privatekey = RSA::createKey(1024)
            ->withHash('sha256')
            ->withMGFHash('sha256')
            ->withPadding(RSA::SIGNATURE_PSS);

        RSA::forceEngine('OpenSSL');
        try {
            $this->expectException(BadConfigurationException::class);
            $privatekey->sign('zzzz');
        } finally {
            RSA::forceEngine();
        }
    }

    public function testSmallModulo(): void
    {
        $this->expectException(KeyConstraintException::class);

        $plaintext = 'x';

        $key = PKCS8::savePublicKey(
            new BigInteger(base64_decode('272435F22706FA96DE26E980D22DFF67'), 256), // n
            new BigInteger(base64_decode('158753FF2AF4D1E5BBAB574D5AE6B54D'), 256)  // e
        );
        $rsa = PublicKeyLoader::load($key);
        $this->assertInstanceOf(PublicKey::class, $rsa);

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
-----END RSA PRIVATE KEY-----');
        $this->assertInstanceOf(PrivateKey::class, $rsa);
        $rsa = $rsa
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

    #[\PHPUnit\Framework\Attributes\Group('github1423')]
    public function testPSSSigsWithNonPowerOf2Key(): void
    {
        $pub = <<<HERE
            -----BEGIN PUBLIC KEY-----
            MF0wDQYJKoZIhvcNAQEBBQADTAAwSQJCAmdYuOvii3I6ya3q/zSeZFoJprgF9fIq
            k12yS6pCS3c+1wZ9cYFVtgfpSL4XpylLe9EnRT2GRVYCqUkR4AUeTuvnAgMBAAE=
            -----END PUBLIC KEY-----
            HERE;

        $rsa = PublicKeyLoader::load($pub);
        $this->assertInstanceOf(PublicKey::class, $rsa);
        $rsa = $rsa
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

        $rsa = PublicKeyLoader::load($pub);
        $this->assertInstanceOf(PublicKey::class, $rsa);
        $rsa = $rsa
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
        $this->assertInstanceOf(PublicKey::class, $rsa);

        $message = 'hello world!';
        $signature = pack('H*', 'a0073057133ff3758e7e111b4d7441f1d8cbe4b2dd5ee4316a14264290dee5ed7f175716639bd9bb43a14e4f9fcb9e84dedd35e2205caac04828b2c053f68176d971ea88534dd2eeec903043c3469fc69c206b2a8694fd262488441ed8852280c3d4994e9d42bd1d575c7024095f1a20665925c2175e089c0d731471f6cc145404edf5559fd2276e45e448086f71c78d0cc6628fad394a34e51e8c10bc39bfe09ed2f5f742cc68bee899d0a41e4c75b7b80afd1c321d89ccd9fe8197c44624d91cc935dfa48de3c201099b5b417be748aef29248527e8bbb173cab76b48478d4177b338fe1f1244e64d7d23f07add560d5ad50b68d6649a49d7bc3db686daaa7');

        $rsa = $rsa->withPadding(RSA::SIGNATURE_PKCS1);
        //$rsa = $rsa->withHash('sha256');

        $engines = ['libsodium', 'OpenSSL', 'PHP', null];
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

    #[\PHPUnit\Framework\Attributes\Group('github1669')]
    public function testOAEPWithLabel(): void
    {
        $publicKey = PublicKeyLoader::load('-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnkFHQbt801+kMnxn0VmMVljp8
XdsbLEziLul3MwwckBDHwW6UDvYjN7vzJ/OM2RTxTbzilDcXJ37Zqz4qlDvXwSNm
gIe+3dpuuRQRrJuJP6FD8zDTkRmg3QWOIIPBTzCqOtJKgWjFwMMxfCOBFEv6Ldn5
Ac0i9ARl0/aNTWjvGwIDAQAB
-----END PUBLIC KEY-----');
        $this->assertInstanceOf(PublicKey::class, $publicKey);

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
        $this->assertInstanceOf(PrivateKey::class, $privateKey);

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
        $this->assertInstanceOf(PublicKey::class, $rsa);
        $this->assertTrue((bool) ($rsa->getPadding() & RSA::SIGNATURE_PSS));
        $rsa = $rsa->withPadding(RSA::ENCRYPTION_NONE);
        $this->assertTrue((bool) ($rsa->getPadding() & RSA::SIGNATURE_PSS));
    }

    #[\PHPUnit\Framework\Attributes\Group('github2132')]
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
        $this->assertInstanceOf(PublicKey::class, $key);
        $sig = 'XPvvcjPAuUq1Ev7BAG63nh+KmXXbY6j0kzBKV2eYgzmuHHL5DmQJDKaHzg3qPkKznxokpQ1c5YG8p1X13vXfGzMFHQ2EHKGrfz8cGRFv8rxU9O8PH1liIqzOQQltcwBdZGdkHC/BY1v0AV9YT6zKZcGgkYgJG5gFLhGdTEr9c5+V98QeP1E27CUYFrhbN13xvkdMt67pIOrVdL4nVSC1XpMOrtDSydsVIR86xITWPbPngjzLwMXuBQ463rdCR0avcYTHUtxego9jVMAn2uAEWTZTMuearQZ/3rdtZejY0SDQbdmBdelGQkWMEOloIne3U5FfS+PPzVu+m64m1joYPbXDel/aZN+vrgkgB+lI2XxT100uji0TDHQ50HmOIxMELGeCXNo93vggMcTC5pmAgCBCIQPXlJFftNUHCqZ2v1set+QJpXsnaeRkRVElPthbuEupUW7Kq0VDqbFOam5M3yD4UAmDoLKkJGJ0uG1YVsqjrRM2EHx/yACmd92/kJcVWBPD4esBqKKkOylbEA1ljE+5EOSq95V1Z09w030WV2p8xh4lBHQHtbuUFLbq1YkZmn6jj7LrBOXEWzspARPNUyaI2xRs3E+Nik2N+Czg1uESsLlo/n+mP+A7Ygtt4bjuL80GT2T6yl8YM/jMmlF78nosWKbDrQI2LPjS/YaZOBI23D2DJJvXex/V9C5+/RgWzX5rl1zFYrPxKP2BKl53HMfR7NP5Rg20hOtdZedRYJtQTNWLfVUYSrXiggHBAgW+EnbxtqWjhtyUFZoIkaupI5DXvy/aJYBKLZaJ19MWeXmJkKMl5O6ADHi8q/Ca5sPah/bH3pn2UsDT0AqEWpTGVzktPhpDEPACqjiHz8mEnU/DNtPHigLytpJFFECkYa4FnC2eCOc8b4AfFl7F/qgCg+lMVLE3fMZ1NWT52w7TYb1DwaqMKWirTfwBF/368/eOCuIdVma3xmD3IMK+y43qZS3qTCR8YfOaIwxrS6T855kH0Cas73fx3eHq2ekwm18s';
        $sig = base64_decode($sig);
        $this->assertTrue($key->withHash('sha3/512')->withMGFHash('sha3/512')->verify('hello world', $sig));
    }

    #[\PHPUnit\Framework\Attributes\Group('github2289')]
    public function testPKCS1SHA512tAndSHA3(): void
    {
        $private = PublicKeyLoader::load('-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALFS4wkhaK97Z1bg
fsep8PQviG7bwEZ7S6f74WDgopls3FxE4PJgKomM/PsIJzINjDrvQzNXGRBvlv2B
WTyjU2FNssgY7n7X0TVD3DUN4j5DHBhzXzwucX0TYcb7DCkvlb83yOsV1Rg5YtKh
UHpYNx5Qtwp5he01qgdXJyOjPVX7AgMBAAECgYBs8UebLHNsnJx4u6QodzgaTbm8
ojYXF1j787wcEObU7BTWe1rYjkyUBZLHh9LM5ZXp/2WB/VjgyC4zwWxZ3N40OuUc
u5Bwn/vI2KcOTQVOCVtsiv4gaMGPdHduBgR4SiKsnPM8VP/j6cxiWej08E7WFy9b
FkLPZc6Zfsxwuw96gQJBAOmuy/XpEzpydOFluWw5GfZ4KqqY0JRnqygR0vcWjgUr
X+VMjOVT2khng2G+GOXJM+O+PBsjtS9eMblz6gr65GkCQQDCQjG+U+2fBUajXcUA
tAHfbOgzA3yY9SrxunJ690ufb3d8MgwKyZ21Q93U8G+hTV9tFwFMiy3zFQ7a2iOf
40rDAkEArCoYIsjhXcJN0nI7tjwroKbP6HhF09C9DPx0zY5UfAKE2E8ZzyuEOqvo
4+5GMaWXEUdqySP5rThcsiFwYT6PYQJAFcV3b75WRllABnUu7BpAj3rUN0tvvnDT
xE3CINfwaMkEWi39vYPFIhieFwxvZmOWi1Jlud9rYe/9PzftgDDoIwJAcnAHdO6c
txAvarWoANzLXQ5iKxQ1I+FGaY2LI/wIVHC9pSof6kPbSsdsOOWLs85Tjuu0J345
bINnZJfGe2e4Lw==
-----END PRIVATE KEY-----')->withPadding(RSA::SIGNATURE_PKCS1);
        $public = $private->getPublicKey();

        // OpenSSL's signatures of 'abc', the second one without the NULL parameters
        $signatures = [
            'sha512/224' => [
                'AwAsF5AomJ73f5gqGW7KXNXrBMnFdcTwW9+z4L/8NJpFjQRYE905ySzZD+Vo6H9egt1ejeCyJC/loya68aV5VT6ZsIFXCHK7PaoosJyDK24OFKvZlaYMCGzFyNC2RqZm96nGGqxq2vpmDsRpQdOKsoMRfIZVMwnbn7AhDd5r63Y=',
                'aSK2ZjV725BUmMZU76WJl30vn+ITW5u7efuYaINQ5PPtVhwKQrsC/VVgPsImvjj1Xg2Cqh59GwwdycIFsoMmwoHph+cvDsbLXMALDXgJDWhbTikZpDr6Dry4zgAsu/b3kdztdzUODHusXj0S+z3MOj/JO47HUi0qxnMqayzqCHU=',
            ],
            'sha512/256' => [
                'h4GHJnBeDfhw7oPEJE/CyQi+iKxSRxRqyDoU4+aYEI3vRgUgxmFyqqidb+2y5aUMuJk6Yc9xoy96iTSnkDYdolsUXSsn1U7D/hhkwIP1N/IQTrKxWP7f2jLyMFcfddOEb+KHFitT/4RiL4r7Kps0nnoSbVeBCadXZC9CoIogf98=',
                'OK3wn8MjDi9zikpbTvIee95cLzPRYTqZO+Pb5tn56hNi5KxoVNBMm6QPDm4XtNKZeCASmvN9UQdxD+F3LKvKELcg1qGYw1445b+nU6Efz081VohWyAqNM4+gxe06x5zevm4zz+mMC0a9ro3NvR+/g1OTamaOnFho1TVkRxdF4lQ=',
            ],
            'sha3/224' => [
                'NsqBCvFDBOeUSJ8Ql3oAx39vJNzc57QmEQLgpT/mKI8YhTWQDpNwnEvvE2XhsYC8zgOjSfikf7ztumL95kW1Z0zdI/k4Gg2nIpg/JcrhcocVcl4pOoq5bZBJfoZD7dvqczvLrKhwtrTkDi5xEk21SKRiTw6CNcdqWtXpy5aos/s=',
                'ORxVopWZEmzUTP+7BEYbmjdQAHBfbbESdHhHq/f7sbBO+X82eWSDYK7O3Tkn2ujU7zqSurW4chyFOFst36aX8eVE+3M5hjDNA9VmaacKIJbGrM1g01tP4mU9vF7eQQLpjROeC8X7FrSwpHGTUi3sp0y9DfXjZv4MQYxuTJUDUPE=',
            ],
            'sha3/256' => [
                'lQn2HrYvVAp0c1x8XWzdkYpLXoopa77lgIgM4nOY8kIFKYjTFJoiTo5+BmF/1/w8usnzny7vNqV8CZPiIFWD0Oqkwa4CyBX/84dNRIvSYseo/Y3EL6cWt4Vh0rGkf2ppMsxWxrI9tamOpjx4x58vmIOrCyUvm8m+EowishuGcP8=',
                'mw+xQvb9Jek3Vr0EBukfVHL5kV3Ki7VDsRew2xhVIgdEXDe61TSrptcnDuXc/roLH3V0GOTfrZI9+Cy5SSeYG6aMIlxXkREUd6c1DEr6dYm80N4ftd3nkv9HBVzOTKdNywY9YyXj0xIpeCXD9kJnxwwoX2lR3/q/zvS4Sd6J0rw=',
            ],
            'sha3/384' => [
                'fn7jtnAULHMaRZP2oPaRfblLUGbgER3D95c4c0h+B+l6hnzuwGjfwj1iCgS+EdfipOWO1jEih+0SxNEq220HzYgPJAOdFtacaQkt4c+9y1C43evjeS4MCkpP9myXmLjY/ZccPNMgGmnTn5wf1oROpMgpVGML+HwS1x0x8z5k5tA=',
                'd18rnaMVLqVMRK4O0MKKwhC6lbBvqrREitfGxAQPBjjUMauvCslhMRyUe3Pkmtlzap2fnY5Nb1FuVnOcnv3rSsHzREocyzVEdQ9uTlQxyWxODNomSwfYC0p2IXl5ttgCsD8zZqZGIIiayF1ZOBb9ZpzxTD6BVEe+irlznJhw/80=',
            ],
            'sha3/512' => [
                'gWCNf4yuKrrRkywcaRdXJcG2Vo9P3rnlFubxCK3fVPkuKf/yBaD+p/4ZSC+5zxGqyOG/vgxWE5jliNxcyYJB7PlyLr9MkhobE0ptDYBG+DcxRkudzmNRzaiiG12EC9Cti8Glmt4HZyF40Ey/XVBMhkxMUQOkXCwZuUAf6yfh9V8=',
                'fs0Ou8Bw8lWXCKr6Na2XRB0IydhXekG5TI0kYFm3bYFlVESUJWaAXMJseF8EUY8C951iS7AH5wi0ooFK8GfcIGHJ9sbBQB+Dx1Y/9vIXtAkR0O0+VlgU2Adm8yJSmu/2ZYWDi0qZ6t53ppth6ssPqDwm/D4hVP/mQHCFRQi+4OY=',
            ],
        ];

        RSA::forceEngine('PHP');
        try {
            foreach ($signatures as $hash => $pair) {
                [$withNull, $withoutNull] = array_map('base64_decode', $pair);
                $this->assertSame($withNull, $private->withHash($hash)->sign('abc'), $hash);
                $this->assertTrue($public->withHash($hash)->verify('abc', $withNull), $hash);
                $this->assertTrue($public->withHash($hash)->verify('abc', $withoutNull), $hash);
            }
        } finally {
            RSA::forceEngine();
        }
    }

    #[\PHPUnit\Framework\Attributes\Group('github2289')]
    public function testGetPublicKeyAndPSSFormatWithSHA512tAndSHA3(): void
    {
        $private = RSA::createKey(1024)->withPadding(RSA::SIGNATURE_PSS);
        foreach ([['sha512/256', 'sha512/224'], ['sha3/256', 'sha3/384']] as [$hash, $mgfHash]) {
            $key = $private->withHash($hash)->withMGFHash($mgfHash);
            $signature = $key->sign('zzzz');

            $this->assertTrue($key->getPublicKey()->verify('zzzz', $signature), $hash);
            $public = PublicKeyLoader::load($key->getPublicKey()->toString('PSS'));
            $this->assertTrue($public->verify('zzzz', $signature), $hash);
        }
    }

    #[\PHPUnit\Framework\Attributes\Group('github2136')]
    public function testEncryptOneKeyDecryptAnotherKey()
    {
        $forcedEngine = RSA::getForcedEngine();
        try {
            $keyA = PublicKeyLoader::load('-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIl4g4CJxwv1jycznIBvWKqAZ5kMPMMw
VGcFdSNBW9LUERIv+wyQH8gJjmf2LN17KyefbSm5LBIyuyD37nIJWRUCAwEAAQ==
-----END PUBLIC KEY-----');
            $this->assertInstanceOf(PublicKey::class, $keyA);

            $keyB = PublicKeyLoader::load('-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA/GaZqSpvCYsgZ4lB
x640dFZEiMgVK0jyvwtY79NPsV44TI2H/Z8ONWBoSw+ZJB1t2dPMKyPUVKwC8wA/
ZGV/0wIDAQABAkA60oiGMcL99OQg7Q6dBD7qS/6d6A9y7oXQO0tHXTZp7cJDfRah
5rhzmSOFMyfQ8wzl/RqmWm26nyiqQoitMSs1AiEAwwV6rgXimDmFGAU0BBIIOjFD
rtx3RFgdiO/lApitgQcCIQFLUhAgMDcLmru1Z0a+bUG/MY81Ahdr0t+pkIqOnpVz
1QIgXVKE5zuXuCJmRx1OS9hZKYejjMyhIgpMb9fkLb7j4AcCIQDTy0Ovr+KgMmun
zLs2Y9VRiTbIZeve61A6rsFD5jAXeQIhAIEBdMO36Skglaotpfi+Jjm5mNhH2B6z
B78AVyeOXhlI
-----END PRIVATE KEY-----');
            $this->assertInstanceOf(PrivateKey::class, $keyB);

            $ct = $keyA->withPadding(RSA::ENCRYPTION_PKCS1)->encrypt('helloworld');

            $engines = ['libsodium', 'OpenSSL', 'PHP'];
            foreach ($engines as $engine) {
                RSA::forceEngine($engine);

                $rejected = false;
                try {
                    $keyB->withPadding(RSA::ENCRYPTION_PKCS1)->decrypt($ct);
                } catch (BadDecryptionException) {
                    $rejected = true;
                } catch (BadConfigurationException) {
                    // This engine cannot perform this operation in the current configuration.
                    continue;
                }

                $this->assertTrue($rejected, "Engine $engine must reject ciphertext encrypted for another key.");
            }
        } finally {
            RSA::forceEngine($forcedEngine);
        }
    }

    public function testBlinding()
    {
        $publicKey = PublicKeyLoader::load('-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnkFHQbt801+kMnxn0VmMVljp8
XdsbLEziLul3MwwckBDHwW6UDvYjN7vzJ/OM2RTxTbzilDcXJ37Zqz4qlDvXwSNm
gIe+3dpuuRQRrJuJP6FD8zDTkRmg3QWOIIPBTzCqOtJKgWjFwMMxfCOBFEv6Ldn5
Ac0i9ARl0/aNTWjvGwIDAQAB
-----END PUBLIC KEY-----');
        $this->assertInstanceOf(PublicKey::class, $publicKey);

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
        $this->assertInstanceOf(PrivateKey::class, $privateKey);

        $data = 'The quick brown fox jumps over the lazy dog';

        RSA::forceEngine('PHP');
        RSA::disableBlinding();

        $sig = $privateKey->sign($data);
        $this->assertTrue($publicKey->verify($data, $sig));

        RSA::enableBlinding();

        $sig = $privateKey->sign($data);
        $this->assertTrue($publicKey->verify($data, $sig));

        RSA::forceEngine();
    }

    #[\PHPUnit\Framework\Attributes\Group('github2164')]
    public function testLongSaltLengthPSS()
    {
        $public = PublicKeyLoader::load('-----BEGIN PUBLIC KEY-----
MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ
7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wP
EyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7Mhh
MTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b
 ODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB
 -----END PUBLIC KEY-----');
        $this->assertInstanceOf(PublicKey::class, $public);
        $msg = 'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ';
        $sig = base64_decode('PPG4xyDVY8ffp4CcxofNmsTDXsrVG2npdQuibLhJbv4ClyPTUtR5giNSvuxo03kB6I8VXVr0Y9X7UxhJVEoJOmULAwRWaUsDnIewQa101cVhMa6iR8X37kfFoiZ6NkS+c7henVkkQWu2HtotkEtQvN5hFlk8IevXXPmvZlhQhwzB1sGzGYnoi1zOfuL98d3BIjUjtlwii5w6gYG2AEEzp7HnHCsb3jIwUPdq86Oe6hIFjtBwduIK90ca4UqzARpcfwxHwVLMpatKask00AgGVI0ysdk0BLMjmLutquD03XbThHScC2C2/Pp4cHWgMzvbgLU2RYYZcZRKr46QeNgz9w==');

        $engines = ['libsodium', 'OpenSSL', 'PHP'];
        foreach ($engines as $engine) {
            try {
                RSA::forceEngine($engine);

                RSA::enableSaltLengthDiscovery();
                $this->assertTrue($public->verify($msg, $sig), "Failed asserting that the long salt validates with $engine and salt length discovery enabled");
                RSA::disableSaltLengthDiscovery();
                $this->assertFalse($public->verify($msg, $sig), "Failed asserting that the long salt validates with $engine and salt length discovery disabled");
            } catch (BadConfigurationException $e) {
            }
        }
        // reset
        RSA::forceEngine();
        RSA::enableSaltLengthDiscovery();
    }
}
