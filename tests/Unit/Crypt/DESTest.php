<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib4\Crypt\DES;
use phpseclib4\Tests\PhpseclibTestCase;

// the AES tests establish the correctness of the modes of operation. this test is inteded to establish the consistency of
// key and iv padding between the multiple engines
class Unit_Crypt_DESTest extends PhpseclibTestCase
{
    public function testEncryptPadding()
    {
        $engines = [
            'PHP',
            'Eval',
            'mcrypt',
            'OpenSSL',
        ];

        foreach ($engines as $engine) {
            $des = new DES('cbc');
            $des->setKey("d\0\0\0\0\0\0\0");
            $des->setIV("d\0\0\0\0\0\0\0");
            if (!$des->isValidEngine($engine)) {
                self::markTestSkipped("Unable to initialize $engine engine");
            }
            $des->setPreferredEngine($engine);

            $result = pack('H*', '3e7613642049af1e');

            $test = $des->encrypt('d');
            $this->assertEquals($result, $test, "Failed asserting that the $engine engine produced the correct result");
        }
    }

    public function testDecryptPadding()
    {
        $engines = [
            'PHP',
            'Eval',
            'mcrypt',
            'OpenSSL',
        ];

        foreach ($engines as $engine) {
            $des = new DES('cbc');
            $des->setKey("\0\0\0\0\0\0\0\0");
            $des->setIV("\0\0\0\0\0\0\0\0");
            $des->disablePadding();
            if (!$des->isValidEngine($engine)) {
                self::markTestSkipped("Unable to initialize $engine engine");
            }
            $des->setPreferredEngine($engine);

            $result = pack('H*', '79b305d1ce555221');

            $test = $des->decrypt("d\0\0\0\0\0\0\0");
            $this->assertEquals($result, $test, "Failed asserting that the $engine engine produced the correct result");
        }
    }
}