<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib3\Math\BigInteger;

class Unit_Math_BigInteger_DefaultTest extends Unit_Math_BigInteger_TestCase
{
    public function getInstance($x = 0, $base = 10)
    {
        return new BigInteger($x, $base);
    }

    public static function getStaticClass()
    {
        return 'phpseclib3\Math\BigInteger';
    }
}
