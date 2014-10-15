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
        self::$engine = CRYPT_MODE_INTERNAL;

        parent::setUpBeforeClass();
    }
}
