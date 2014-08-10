<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIV Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Unit_Crypt_Hash_SHA256_96Test extends Unit_Crypt_Hash_SHA256Test
{
    public function getInstance()
    {
        return new Crypt_Hash('sha256-96');
    }

    static public function hashData()
    {
        $tests = parent::hashData();
        foreach ($tests as &$test) {
            $test[1] = substr($test[1], 0, 24);
        }
        return $tests;
    }

    static public function hmacData()
    {
        $tests = parent::hashData();
        foreach ($tests as &$test) {
            $test[3] = substr($test[3], 0, 24);
        }
        return $tests;
    }
}
