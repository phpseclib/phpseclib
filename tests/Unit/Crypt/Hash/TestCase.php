<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2012 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Hash;

abstract class Unit_Crypt_Hash_TestCase extends PhpseclibTestCase
{
    public static function setUpBeforeClass()
    {
        if (!defined('CRYPT_HASH_MODE')) {
            define('CRYPT_HASH_MODE', Hash::MODE_INTERNAL);
        }
    }

    public function setUp()
    {
        if (defined('CRYPT_HASH_MODE') && CRYPT_HASH_MODE !== Hash::MODE_INTERNAL) {
            $this->markTestSkipped(
                'Skipping test because CRYPT_HASH_MODE is not defined as \phpseclib\Crypt\Hash::MODE_INTERNAL.'
            );
        }
    }

    protected function assertHashesTo(Hash $hash, $message, $expected)
    {
        $this->assertEquals(
            strtolower($expected),
            bin2hex($hash->hash($message)),
            sprintf("Failed asserting that '%s' hashes to '%s'.", $message, $expected)
        );
    }

    protected function assertHMACsTo(Hash $hash, $key, $message, $expected)
    {
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
}
