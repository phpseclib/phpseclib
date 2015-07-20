<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\AES;
use phpseclib\Crypt\Base;
use phpseclib\Crypt\Rijndael;

abstract class Unit_Crypt_AES_TestCase extends PhpseclibTestCase
{
    protected $engine;

    private function _checkEngine($aes)
    {
        if ($aes->getEngine() != $this->engine) {
            $engine = 'internal';
            switch ($this->engine) {
                case Base::ENGINE_OPENSSL:
                    $engine = 'OpenSSL';
                    break;
                case Base::ENGINE_MCRYPT:
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
            Base::MODE_CTR,
            Base::MODE_OFB,
            Base::MODE_CFB,
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
        $aes = new AES($mode);
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

        $aes = new Rijndael();
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

        $aes = new AES();
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
            Base::MODE_CTR,
            Base::MODE_OFB,
            Base::MODE_CFB,
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

        $aes = new AES($mode);
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

        $aes = new AES($mode);
        $aes->setPreferredEngine($this->engine);
        $aes->enableContinuousBuffer();
        $aes->setKey($key);
        $aes->setIV($iv);

        if (!$this->_checkEngine($aes)) {
            return;
        }

        foreach ($test as $len) {
            $temp = str_repeat('d', $len);
            $output = $aes->$op($temp);
            $result.= $output;
        }

        $c2 = $result;

        $this->assertSame(bin2hex($c1), bin2hex($c2));
    }

    /**
    * @dataProvider continuousBufferBatteryCombos
    */
    // pretty much the same as testContinuousBufferBattery with the caveat that continuous mode is not enabled
    public function testNonContinuousBufferBattery($op, $mode, $test)
    {
        if (count($test) == 1) {
            return;
        }

        $iv = str_repeat('x', 16);
        $key = str_repeat('a', 16);

        $aes = new AES($mode);
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

        $aes = new AES($mode);
        $aes->setPreferredEngine($this->engine);
        $aes->setKey($key);
        $aes->setIV($iv);

        $this->_checkEngine($aes);

        foreach ($test as $len) {
            $temp = str_repeat('d', $len);
            $output = $aes->$op($temp);
            $result.= $output;
        }

        $c2 = $result;

        $this->assertNotSame(bin2hex($c1), bin2hex($c2));
    }

    // from http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf#page=16
    public function testGFSBox128()
    {
        $aes = new AES();

        $aes->setKey(pack('H*', '00000000000000000000000000000000'));
        $aes->setIV(pack('H*', '00000000000000000000000000000000'));
        $aes->disablePadding();

        $aes->setPreferredEngine($this->engine);
        $this->_checkEngine($aes);

        $result = bin2hex($aes->encrypt(pack('H*', 'f34481ec3cc627bacd5dc3fb08f273e6')));
        $this->assertSame($result, '0336763e966d92595a567cc9ce537f5e');
        $result = bin2hex($aes->encrypt(pack('H*', '9798c4640bad75c7c3227db910174e72')));
        $this->assertSame($result, 'a9a1631bf4996954ebc093957b234589');
        $result = bin2hex($aes->encrypt(pack('H*', '96ab5c2ff612d9dfaae8c31f30c42168')));
        $this->assertSame($result, 'ff4f8391a6a40ca5b25d23bedd44a597');
        $result = bin2hex($aes->encrypt(pack('H*', '6a118a874519e64e9963798a503f1d35')));
        $this->assertSame($result, 'dc43be40be0e53712f7e2bf5ca707209');
        $result = bin2hex($aes->encrypt(pack('H*', 'cb9fceec81286ca3e989bd979b0cb284')));
        $this->assertSame($result, '92beedab1895a94faa69b632e5cc47ce');
        $result = bin2hex($aes->encrypt(pack('H*', 'b26aeb1874e47ca8358ff22378f09144')));
        $this->assertSame($result, '459264f4798f6a78bacb89c15ed3d601');
        $result = bin2hex($aes->encrypt(pack('H*', '58c8e00b2631686d54eab84b91f0aca1')));
        $this->assertSame($result, '08a4e2efec8a8e3312ca7460b9040bbf');
    }

    public function testGFSBox192()
    {
        $aes = new AES();

        $aes->setKey(pack('H*', '000000000000000000000000000000000000000000000000'));
        $aes->setIV(pack('H*', '00000000000000000000000000000000'));
        $aes->disablePadding();

        $aes->setPreferredEngine($this->engine);
        $this->_checkEngine($aes);

        $result = bin2hex($aes->encrypt(pack('H*', '1b077a6af4b7f98229de786d7516b639')));
        $this->assertSame($result, '275cfc0413d8ccb70513c3859b1d0f72');
        $result = bin2hex($aes->encrypt(pack('H*', '9c2d8842e5f48f57648205d39a239af1')));
        $this->assertSame($result, 'c9b8135ff1b5adc413dfd053b21bd96d');
        $result = bin2hex($aes->encrypt(pack('H*', 'bff52510095f518ecca60af4205444bb')));
        $this->assertSame($result, '4a3650c3371ce2eb35e389a171427440');
        $result = bin2hex($aes->encrypt(pack('H*', '51719783d3185a535bd75adc65071ce1')));
        $this->assertSame($result, '4f354592ff7c8847d2d0870ca9481b7c');
        $result = bin2hex($aes->encrypt(pack('H*', '26aa49dcfe7629a8901a69a9914e6dfd')));
        $this->assertSame($result, 'd5e08bf9a182e857cf40b3a36ee248cc');
        $result = bin2hex($aes->encrypt(pack('H*', '941a4773058224e1ef66d10e0a6ee782')));
        $this->assertSame($result, '067cd9d3749207791841562507fa9626');
    }

    public function testGFSBox256()
    {
        $aes = new AES();

        $aes->setKey(pack('H*', '00000000000000000000000000000000' . '00000000000000000000000000000000'));
        $aes->setIV(pack('H*', '00000000000000000000000000000000'));
        $aes->disablePadding();

        $aes->setPreferredEngine($this->engine);
        $this->_checkEngine($aes);

        $result = bin2hex($aes->encrypt(pack('H*', '014730f80ac625fe84f026c60bfd547d')));
        $this->assertSame($result, '5c9d844ed46f9885085e5d6a4f94c7d7');
        $result = bin2hex($aes->encrypt(pack('H*', '0b24af36193ce4665f2825d7b4749c98')));
        $this->assertSame($result, 'a9ff75bd7cf6613d3731c77c3b6d0c04');
        $result = bin2hex($aes->encrypt(pack('H*', '761c1fe41a18acf20d241650611d90f1')));
        $this->assertSame($result, '623a52fcea5d443e48d9181ab32c7421');
        $result = bin2hex($aes->encrypt(pack('H*', '8a560769d605868ad80d819bdba03771')));
        $this->assertSame($result, '38f2c7ae10612415d27ca190d27da8b4');
        $result = bin2hex($aes->encrypt(pack('H*', '91fbef2d15a97816060bee1feaa49afe')));
        $this->assertSame($result, '1bc704f1bce135ceb810341b216d7abe');
    }
}
