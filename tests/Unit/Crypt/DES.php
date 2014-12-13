<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'Crypt/DES.php';

// the AES tests establish the correctness of the modes of operation. this test is inteded to establish the consistency of
// key and iv padding between the multiple engines
class Unit_Crypt_DES_TestCase extends PhpseclibTestCase
{
    public function testEncryptPadding()
    {
        $des = new Crypt_DES(CRYPT_MODE_CBC);
        $des->setKey('d');
        $des->setIV('d');

        $des->setPreferredEngine(CRYPT_ENGINE_INTERNAL);
        $internal = $des->encrypt('d');

        $des->setPreferredEngine(CRYPT_ENGINE_MCRYPT);
        if ($des->getEngine() == CRYPT_ENGINE_MCRYPT) {
            $mcrypt = $des->encrypt('d');
            $this->assertEquals($internal, $mcrypt, 'Failed asserting that the internal and mcrypt engines produce identical results');
        } else {
            self::markTestSkipped('Unable to initialize mcrypt engine');
        }

        $des->setPreferredEngine(CRYPT_ENGINE_OPENSSL);
        if ($des->getEngine() == CRYPT_ENGINE_OPENSSL) {
            $openssl = $des->encrypt('d');
            $this->assertEquals($internal, $openssl,  'Failed asserting that the internal and OpenSSL engines produce identical results');
        } else {
            self::markTestSkipped('Unable to initialize OpenSSL engine');
        }
    }

    // phpseclib null pads ciphertext's if they're not long enough and you're in ecb / cbc mode. this silent failure mode is consistent
    // with mcrypt's behavior. maybe throwing an exception would be better but whatever. this test is more intended to establish consistent
    // behavior between the various engine's
    public function testDecryptPadding()
    {
        $des = new Crypt_DES(CRYPT_MODE_CBC);
        // when the key and iv are not specified they should be null padded
        //$des->setKey();
        //$des->setIV();

        $des->setPreferredEngine(CRYPT_ENGINE_INTERNAL);
        $internal = $des->decrypt('d');

        $des->setPreferredEngine(CRYPT_ENGINE_MCRYPT);
        if ($des->getEngine() == CRYPT_ENGINE_MCRYPT) {
            $mcrypt = $des->decrypt('d');
            $this->assertEquals($internal, $mcrypt, 'Failed asserting that the internal and mcrypt engines produce identical results');
        } else {
            self::markTestSkipped('Unable to initialize mcrypt engine');
        }

        $des->setPreferredEngine(CRYPT_ENGINE_OPENSSL);
        if ($des->getEngine() == CRYPT_ENGINE_OPENSSL) {
            $openssl = $des->decrypt('d');
            $this->assertEquals($internal, $openssl,  'Failed asserting that the internal and OpenSSL engines produce identical results');
        } else {
            self::markTestSkipped('Unable to initialize OpenSSL engine');
        }
    }
}
