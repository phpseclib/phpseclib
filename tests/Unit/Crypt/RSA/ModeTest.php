<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2013 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'Crypt/RSA.php' ;

class Unit_Crypt_RSA_ModeTest extends PhpseclibTestCase
{
    public function testEncryptionModeNone()
    {
        $plaintext = 'a';

        $rsa = new Crypt_RSA();

        extract($rsa->createKey());
        $rsa->loadKey($publickey);

        $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_NONE);
        $a = $rsa->encrypt($plaintext);
        $b = $rsa->encrypt($plaintext);

        $this->assertEquals($a, $b);

        $rsa->loadKey($privatekey);
        $this->assertEquals(trim($rsa->decrypt($a), "\0"), $plaintext);
    }
}
