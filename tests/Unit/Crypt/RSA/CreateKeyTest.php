<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\RSA;
use phpseclib\Crypt\RSA\PKCS1;

class Unit_Crypt_RSA_CreateKeyTest extends PhpseclibTestCase
{
    public function testCreateKey()
    {
        extract(RSA::createKey(768));
        $this->assertInstanceOf('\phpseclib\Crypt\RSA', $privatekey);
        $this->assertInstanceOf('\phpseclib\Crypt\RSA', $publickey);
        $this->assertNotEmpty("$privatekey");
        $this->assertNotEmpty("$publickey");
        $this->assertSame($privatekey->getLength(), 768);
        $this->assertSame($publickey->getLength(), 768);

        return array($publickey, $privatekey);
    }

    /**
     * @depends testCreateKey
     */
    public function testEncryptDecrypt($args)
    {
        list($publickey, $privatekey) = $args;
        $ciphertext = $publickey->encrypt('zzz');
        $this->assertInternalType('string', $ciphertext);
        $plaintext = $privatekey->decrypt($ciphertext);
        $this->assertSame($plaintext, 'zzz');
    }

    public function testMultiPrime()
    {
        RSA::setEngine(RSA::ENGINE_INTERNAL);
        RSA::setSmallestPrime(256);
        extract(RSA::createKey(1024));
        $this->assertInstanceOf('\phpseclib\Crypt\RSA', $privatekey);
        $this->assertInstanceOf('\phpseclib\Crypt\RSA', $publickey);
        $privatekey->setPrivateKeyFormat('PKCS1');
        $this->assertNotEmpty("$privatekey");
        $this->assertNotEmpty("$publickey");
        $this->assertSame($privatekey->getLength(), 1024);
        $this->assertSame($publickey->getLength(), 1024);
        $r = PKCS1::load("$privatekey");
        $this->assertCount(4, $r['primes']);
        // the last prime number could be slightly over. eg. 99 * 99 == 9801 but 10 * 10 = 100. the more numbers you're
        // multiplying the less certain you are to have each of them multiply to an n-bit number
        foreach (array_slice($r['primes'], 0, 3) as $i => $prime) {
            $this->assertSame($prime->getLength(), 256);
        }

        $rsa = new RSA();
        $rsa->load($privatekey->getPrivateKey());
        $signature = $rsa->sign('zzz');
        $rsa->load($rsa->getPublicKey());
        $this->assertTrue($rsa->verify('zzz', $signature));
    }
}
