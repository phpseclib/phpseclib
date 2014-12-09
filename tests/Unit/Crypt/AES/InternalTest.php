<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\AES;
use phpseclib\Crypt\Rijndael;

class Unit_Crypt_AES_InternalTest extends Unit_Crypt_AES_TestCase
{
    static public function setUpBeforeClass()
    {
        parent::setUpBeforeClass();

        self::ensureConstant('CRYPT_AES_ENGINE', AES::ENGINE_INTERNAL);
        self::ensureConstant('CRYPT_RIJNDAEL_ENGINE', Rijndael::ENGINE_INTERNAL);
    }
}
