<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Hash;

class Unit_Crypt_Hash_SHA512_96Test extends Unit_Crypt_Hash_SHA512Test
{
    public function getInstance()
    {
        return new Hash('sha512-96');
    }

    /**
     * @dataProvider hashData()
     */
    public function testHash($message, $longResult)
    {
        parent::testHash($message, substr($longResult, 0, 24));
    }

    /**
     * @dataProvider hmacData()
     */
    public function testHMAC($key, $message, $longResult)
    {
        parent::testHMAC($key, $message, substr($longResult, 0, 24));
    }
}
