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

        self::ensureConstant('CRYPT_ENGINE', Crypt_Base::ENGINE_INTERNAL);
    }
}
