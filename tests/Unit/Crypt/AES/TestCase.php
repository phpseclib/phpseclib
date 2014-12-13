<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'Crypt/AES.php';

abstract class Unit_Crypt_AES_TestCase extends PhpseclibTestCase
{
    protected $engine;

    private function _checkEngine($aes)
    {
        if ($aes->getEngine() != $this->engine) {
            $engine = 'internal';
            switch ($this->engine) {
                case CRYPT_MODE_OPENSSL:
                    $engine = 'OpenSSL';
                    break;
                case CRYPT_MODE_MCRYPT:
                    $engine = 'mcrypt';
            }
            self::markTestSkipped('Unable to initialize ' . $engine . ' engine');
        }
    }

    /**
    * Produces all combinations of test values.
    *
    * @return array
    */
    public function continuousBufferCombos()
    {
        $modes = array(
            'CRYPT_AES_MODE_CTR',
            'CRYPT_AES_MODE_OFB',
            'CRYPT_AES_MODE_CFB',
        );
        $plaintexts = array(
            '',
            '12345678901234567', // https://github.com/phpseclib/phpseclib/issues/39
            "\xDE\xAD\xBE\xAF",
            ':-):-):-):-):-):-)', // https://github.com/phpseclib/phpseclib/pull/43
        );
        $ivs = array(
            '',
            'test123',
        );
        $keys = array(
            '',
            ':-8', // https://github.com/phpseclib/phpseclib/pull/43
            'FOOBARZ',
        );

        $result = array();

        // @codingStandardsIgnoreStart
        foreach ($modes as $mode)
        foreach ($plaintexts as $plaintext)
        foreach ($ivs as $iv)
        foreach ($keys as $key)
            $result[] = array($mode, $plaintext, $iv, $key);
        // @codingStandardsIgnoreEnd

        return $result;
    }

    /**
    * @dataProvider continuousBufferCombos
    */
    public function testEncryptDecryptWithContinuousBuffer($mode, $plaintext, $iv, $key)
    {
        $aes = new Crypt_AES(constant($mode));
        $aes->setPreferredEngine($this->engine);
        $aes->enableContinuousBuffer();
        $aes->setIV($iv);
        $aes->setKey($key);

        $this->_checkEngine($aes);

        $actual = '';
        for ($i = 0, $strlen = strlen($plaintext); $i < $strlen; ++$i) {
            $actual .= $aes->decrypt($aes->encrypt($plaintext[$i]));
        }

        $this->assertEquals($plaintext, $actual);
    }

    /**
    * @group github451
    */
    public function testKeyPaddingRijndael()
    {
        // this test case is from the following URL:
        // https://web.archive.org/web/20070209120224/http://fp.gladman.plus.com/cryptography_technology/rijndael/aesdvec.zip

        $aes = new Crypt_Rijndael();
        $aes->setPreferredEngine($this->engine);
        $aes->disablePadding();
        $aes->setKey(pack('H*', '2b7e151628aed2a6abf7158809cf4f3c762e7160')); // 160-bit key. Valid in Rijndael.
        //$this->_checkEngine($aes); // should only work in internal mode
        $ciphertext = $aes->encrypt(pack('H*', '3243f6a8885a308d313198a2e0370734'));
        $this->assertEquals($ciphertext, pack('H*', '231d844639b31b412211cfe93712b880'));
    }

    /**
    * @group github451
    */
    public function testKeyPaddingAES()
    {
        // same as the above - just with a different ciphertext

        $aes = new Crypt_AES();
        $aes->setPreferredEngine($this->engine);
        $aes->disablePadding();
        $aes->setKey(pack('H*', '2b7e151628aed2a6abf7158809cf4f3c762e7160')); // 160-bit key. AES should null pad to 192-bits
        $this->_checkEngine($aes);
        $ciphertext = $aes->encrypt(pack('H*', '3243f6a8885a308d313198a2e0370734'));
        $this->assertEquals($ciphertext, pack('H*', 'c109292b173f841b88e0ee49f13db8c0'));
    }

    /**
    * Produces all combinations of test values.
    *
    * @return array
    */
    public function continuousBufferBatteryCombos()
    {
        $modes = array(
            'CRYPT_MODE_CTR',
            'CRYPT_MODE_OFB',
            'CRYPT_MODE_CFB',
        );

        $combos = array(
             array(16),
             array(17),
             array(1, 16),
             array(3, 6, 7), // (3 to test the openssl_encrypt call and the buffer creation, 6 to test the exclusive use of the buffer and 7 to test the buffer's exhaustion and recreation)
            array(15, 4), // (15 to test openssl_encrypt call and buffer creation and 4 to test something that spans multpile bloc
            array(3, 6, 10, 16), // this is why the strlen check in the buffer-only code was needed
            array(16, 16), // two full size blocks
            array(3, 6, 7, 16), // partial block + full size block
            array(16, 3, 6, 7),
            // a few others just for fun
            array(32,32),
            array(31,31),
            array(17,17),
            array(99, 99)
        );

        $result = array();

        // @codingStandardsIgnoreStart
        foreach ($modes as $mode)
        foreach ($combos as $combo)
        foreach (array('encrypt', 'decrypt') as $op)
            $result[] = array($op, $mode, $combo);
        // @codingStandardsIgnoreEnd

        return $result;
    }

    /**
    * @dataProvider continuousBufferBatteryCombos
    */
    public function testContinuousBufferBattery($op, $mode, $test)
    {
        $iv = str_repeat('x', 16);
        $key = str_repeat('a', 16);

        $aes = new Crypt_AES(constant($mode));
        $aes->setPreferredEngine($this->engine);
        $aes->setKey($key);
        $aes->setIV($iv);

        $this->_checkEngine($aes);

        $str = '';
        $result = '';
        foreach ($test as $len) {
            $temp = str_repeat('d', $len);
            $str.= $temp;
        }

        $c1 = $aes->$op($str);

        $aes = new Crypt_AES(constant($mode));
        $aes->setPreferredEngine($this->engine);
        $aes->enableContinuousBuffer();
        $aes->setKey($key);
        $aes->setIV($iv);

        $this->_checkEngine($aes);

        foreach ($test as $len) {
            $temp = str_repeat('d', $len);
            $output = $aes->$op($temp);
            $result.= $output;
        }

        $c2 = $result;

        $this->assertSame(bin2hex($c1), bin2hex($c2));
    }
}
