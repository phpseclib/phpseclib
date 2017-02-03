<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Common\BlockCipher;

class Unit_Crypt_AES_EvalTest extends Unit_Crypt_AES_TestCase
{
    protected function setUp()
    {
        $this->engine = BlockCipher::ENGINE_EVAL;
    }
}
