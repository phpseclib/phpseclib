<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2012 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Hash;

class Unit_Crypt_HashTest extends PhpseclibTestCase
{
    protected function assertHashesTo($hash, $message, $expected)
    {
        $hash = new Hash($hash);

        $this->assertEquals(
            strtolower($expected),
            bin2hex($hash->hash($message)),
            sprintf("Failed asserting that '%s' hashes to '%s'.", $message, $expected)
        );
    }

    protected function assertHMACsTo($hash, $key, $message, $expected)
    {
        $hash = new Hash($hash);
        $hash->setKey($key);

        $this->assertEquals(
            strtolower($expected),
            bin2hex($hash->hash($message)),
            sprintf(
                "Failed asserting that '%s' HMACs to '%s' with key '%s'.",
                $message,
                $expected,
                $key
            )
        );
    }

    public static function hashData()
    {
        return array(
            array('md5', '', 'd41d8cd98f00b204e9800998ecf8427e'),
            array('md5', 'The quick brown fox jumps over the lazy dog', '9e107d9d372bb6826bd81d3542a419d6'),
            array('md5', 'The quick brown fox jumps over the lazy dog.', 'e4d909c290d0fb1ca068ffaddf22cbd0'),
            array(
                'sha256',
                '',
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            ),
            array(
                'sha256',
                'The quick brown fox jumps over the lazy dog',
                'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
            ),
            array(
                'sha256',
                'The quick brown fox jumps over the lazy dog.',
                'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c',
            ),
            array(
                'sha512',
                '',
                'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
            ),
            array(
                'sha512',
                'The quick brown fox jumps over the lazy dog',
                '07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6',
            ),
            array(
                'sha512',
                'The quick brown fox jumps over the lazy dog.',
                '91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed',
            ),
        );
    }

    /**
     * @dataProvider hmacData()
     */
    public function testHMAC($hash, $key, $message, $result)
    {
        $this->assertHMACsTo($hash, $key, $message, $result);
    }

    /**
     * @dataProvider hmacData()
     */
    public function testHMAC96($hash, $key, $message, $result)
    {
        $this->assertHMACsTo($hash . '-96', $key, $message, substr($result, 0, 24));
    }

    public static function hmacData()
    {
        return array(
            array('md5', '', '', '74e6f7298a9c2d168935f58c001bad88'),
            array('md5', 'key', 'The quick brown fox jumps over the lazy dog', '80070713463e7749b90c2dc24911e275'),
            // RFC 4231
            // Test Case 1
            array(
                'sha256',
                pack('H*', '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
                pack('H*', '4869205468657265'),
                'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
            ),
            // Test Case 2
            array(
                'sha256',
                pack('H*', '4a656665'),
                pack('H*', '7768617420646f2079612077616e7420666f72206e6f7468696e673f'),
                '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
            ),
            // Test Case 3
            array(
                'sha256',
                pack('H*', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                pack('H*', 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'),
                '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
            ),
            // Test Case 4
            array(
                'sha256',
                pack('H*', '0102030405060708090a0b0c0d0e0f10111213141516171819'),
                pack('H*', 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd'),
                '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
            ),
            // RFC 4231
            // Test Case 1
            array(
                'sha512',
                pack('H*', '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
                pack('H*', '4869205468657265'),
                '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
            ),
            // Test Case 2
            array(
                'sha512',
                pack('H*', '4a656665'),
                pack('H*', '7768617420646f2079612077616e7420666f72206e6f7468696e673f'),
                '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
            ),
            // Test Case 3
            array(
                'sha512',
                pack('H*', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                pack('H*', 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'),
                'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
            ),
            // Test Case 4
            array(
                'sha512',
                pack('H*', '0102030405060708090a0b0c0d0e0f10111213141516171819'),
                pack('H*', 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd'),
                'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
            ),

        );
    }

    /**
     * @dataProvider hashData()
     */
    public function testHash($hash, $message, $result)
    {
        $this->assertHashesTo($hash, $message, $result);
    }

    /**
     * @dataProvider hashData()
     */
    public function testHash96($hash, $message, $result)
    {
        $this->assertHashesTo($hash . '-96', $message, substr($result, 0, 24));
    }
}
