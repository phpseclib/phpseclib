<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Base;
use phpseclib\Crypt\DES;

// the AES tests establish the correctness of the modes of operation. this test is inteded to establish the consistency of
// key and iv padding between the multiple engines
class Unit_Crypt_DESTest extends PhpseclibTestCase
{
    public function testEncryptPadding()
    {
        $des = new DES(Base::MODE_CBC);
        $des->setKey('d');
        $des->setIV('d');

        $des->setPreferredEngine(Base::ENGINE_INTERNAL);

        $result = pack('H*', '3e7613642049af1e');

        $internal = $des->encrypt('d');
        $this->assertEquals($result, $internal, 'Failed asserting that the internal engine produced the correct result');

        $des->setPreferredEngine(Base::ENGINE_MCRYPT);
        if ($des->getEngine() == Base::ENGINE_MCRYPT) {
            $mcrypt = $des->encrypt('d');
            $this->assertEquals($result, $mcrypt, 'Failed asserting that the mcrypt engine produced the correct result');
        } else {
            self::markTestSkipped('Unable to initialize mcrypt engine');
        }

        $des->setPreferredEngine(Base::ENGINE_OPENSSL);
        if ($des->getEngine() == Base::ENGINE_OPENSSL) {
            $openssl = $des->encrypt('d');
            $this->assertEquals($result, $openssl,  'Failed asserting that the OpenSSL engine produced the correct result');
        } else {
            self::markTestSkipped('Unable to initialize OpenSSL engine');
        }
    }

    // phpseclib null pads ciphertext's if they're not long enough and you're in ecb / cbc mode. this silent failure mode is consistent
    // with mcrypt's behavior. maybe throwing an exception would be better but whatever. this test is more intended to establish consistent
    // behavior between the various engine's
    public function testDecryptPadding()
    {
        $des = new DES(Base::MODE_CBC);
        $des->disablePadding();
        // when the key and iv are not specified they should be null padded
        //$des->setKey();
        //$des->setIV();

        $des->setPreferredEngine(Base::ENGINE_INTERNAL);
        $internal = $des->decrypt('d');

        $result = pack('H*', '79b305d1ce555221');
        $this->assertEquals($result, $internal, 'Failed asserting that the internal engine produced the correct result');

        $des->setPreferredEngine(Base::ENGINE_MCRYPT);
        if ($des->getEngine() == Base::ENGINE_MCRYPT) {
            $mcrypt = $des->decrypt('d');
            $this->assertEquals($result, $mcrypt, 'Failed asserting that the mcrypt engine produced the correct result');
        } else {
            self::markTestSkipped('Unable to initialize mcrypt engine');
        }

        $des->setPreferredEngine(Base::ENGINE_OPENSSL);
        if ($des->getEngine() == Base::ENGINE_OPENSSL) {
            $openssl = $des->decrypt('d');
            $this->assertEquals($result, $openssl,  'Failed asserting that the OpenSSL engine produced the correct result');
        } else {
            self::markTestSkipped('Unable to initialize OpenSSL engine');
        }
    }
}
