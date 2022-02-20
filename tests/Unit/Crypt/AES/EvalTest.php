<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */


class Unit_Crypt_AES_EvalTest extends Unit_Crypt_AES_TestCase
{
    protected function setUp()
    {
        $this->engine = 'Eval';
    }
}
