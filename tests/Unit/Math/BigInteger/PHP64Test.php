<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib3\Math\BigInteger\Engines\PHP64;

class Unit_Math_BigInteger_PHP64Test extends Unit_Math_BigInteger_TestCase
{
    public static function setUpBeforeClass()
    {
        if (!PHP64::isValidEngine()) {
            self::markTestSkipped('64-bit integers are not available.');
        }
        PHP64::setModExpEngine('DefaultEngine');
    }

    public function getInstance($x = 0, $base = 10)
    {
        return new PHP64($x, $base);
    }

    public function testInternalRepresentation()
    {
        $x = new PHP64('FFFFFFFFFFFFFFFFC90FDA', 16);
        $y = new PHP64("$x");

        $this->assertSame(self::getVar($x, 'value'), self::getVar($y, 'value'));
    }

    public static function getStaticClass()
    {
        return 'phpseclib3\Math\BigInteger\Engines\PHP64';
    }
}
