<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Unit_Crypt_AES_InternalTest extends Unit_Crypt_AES_TestCase
{
    static public function setUpBeforeClass()
    {
        parent::setUpBeforeClass();

        self::ensureConstant('CRYPT_AES_MODE', Crypt_AES::ENGINE_INTERNAL);
        self::ensureConstant('CRYPT_RIJNDAEL_MODE', Crypt_Rijndael::ENGINE_INTERNAL);
    }
}
