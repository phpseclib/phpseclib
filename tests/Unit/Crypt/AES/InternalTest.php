<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Unit_Crypt_AES_InternalTest extends Unit_Crypt_AES_TestCase
{
    static public function setUpBeforeClass()
    {
        parent::setUpBeforeClass();

        self::ensureConstant('CRYPT_AES_ENGINE', Crypt_AES::ENGINE_INTERNAL);
        self::ensureConstant('CRYPT_RIJNDAEL_ENGINE', Crypt_Rijndael::ENGINE_INTERNAL);
    }
}
