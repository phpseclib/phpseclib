<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\RSA;

class Unit_Crypt_RSA_CreateKeyTest extends PhpseclibTestCase
{
    public function testCreateKey()
    {
        extract(RSA::createKey(512));
        $this->assertInstanceOf('\phpseclib\Crypt\RSA', $privatekey);
        $this->assertInstanceOf('\phpseclib\Crypt\RSA', $publickey);
        $this->assertNotEmpty("$privatekey");
        $this->assertNotEmpty("$publickey");

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
}
