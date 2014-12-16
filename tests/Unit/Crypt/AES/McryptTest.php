<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Base;

class Unit_Crypt_AES_McryptTest extends Unit_Crypt_AES_TestCase
{
    static public function setUpBeforeClass()
    {
        if (!extension_loaded('mcrypt')) {
            self::markTestSkipped('mcrypt extension is not available.');
        }

        parent::setUpBeforeClass();

        self::ensureConstant('CRYPT_AES_MODE', Base::ENGINE_MCRYPT);
        self::ensureConstant('CRYPT_RIJNDAEL_MODE', Base::ENGINE_MCRYPT);
    }
}
