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

    private function checkEngine($aes)
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
            //'CRYPT_AES_MODE_OFB',
            //'CRYPT_AES_MODE_CFB',
        );
        $plaintexts = array(
            //'',
            '12345678901234567', // https://github.com/phpseclib/phpseclib/issues/39
            //"\xDE\xAD\xBE\xAF",
            //':-):-):-):-):-):-)', // https://github.com/phpseclib/phpseclib/pull/43
        );
        $ivs = array(
            '',
            //'test123',
        );
        $keys = array(
            '',
            //':-8', // https://github.com/phpseclib/phpseclib/pull/43
            //'FOOBARZ',
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

        $this->checkEngine($aes);

global $zzzz;
$zzzz = func_get_args();

        $actual = '';
        for ($i = 0, $strlen = strlen($plaintext); $i < $strlen; ++$i) {
            $actual .= $aes->decrypt($aes->encrypt($plaintext[$i]));
        }

        $this->assertEquals($plaintext, $actual);
    }

}