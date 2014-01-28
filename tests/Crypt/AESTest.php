<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib\Crypt;

use phpseclib\Crypt\AES;

abstract class AESTest extends \phpseclib\AbstractTestCase
{
    static public function setUpBeforeClass()
    {
        AES::setMode(AES::MODE_INTERNAL);
    }

    public function setUp()
    {
        if (AES::getMode() !== AES::MODE_INTERNAL)
        {
            $this->markTestSkipped('Skipping test because AES::$mode is not defined as AES::MODE_INTERNAL.');
        }
    }
}
