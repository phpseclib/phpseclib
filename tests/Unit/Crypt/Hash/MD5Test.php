<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2012 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Hash;

class Unit_Crypt_Hash_MD5Test extends Unit_Crypt_Hash_TestCase
{
    public function getInstance()
    {
        return new Hash('md5');
    }

    /**
     * @dataProvider hashData()
     */
    public function testHash($message, $result)
    {
        $this->assertHashesTo($this->getInstance(), $message, $result);
    }

    public static function hashData()
    {
        return array(
            array('', 'd41d8cd98f00b204e9800998ecf8427e'),
            array('The quick brown fox jumps over the lazy dog', '9e107d9d372bb6826bd81d3542a419d6'),
            array('The quick brown fox jumps over the lazy dog.', 'e4d909c290d0fb1ca068ffaddf22cbd0'),
        );
    }

    /**
     * @dataProvider hmacData()
     */
    public function testHMAC($key, $message, $result)
    {
        $this->assertHMACsTo($this->getInstance(), $key, $message, $result);
    }

    public static function hmacData()
    {
        return array(
            array('', '', '74e6f7298a9c2d168935f58c001bad88'),
            array('key', 'The quick brown fox jumps over the lazy dog', '80070713463e7749b90c2dc24911e275'),
        );
    }
}
