<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib3\Math\BigInteger\Engines\PHP32;

class Unit_Math_BigInteger_PHP32Test extends Unit_Math_BigInteger_TestCase
{
    public static function setUpBeforeClass()
    {
        if (version_compare(PHP_VERSION, '7.0.0') < 0) {
            self::markTestSkipped('32-bit integers slow things down too much on PHP 5.6');
        }

        PHP32::setModExpEngine('DefaultEngine');
    }

    public function getInstance($x = 0, $base = 10)
    {
        return new PHP32($x, $base);
    }

    public function testInternalRepresentation()
    {
        $x = new PHP32('FFFFFFFFFFFFFFFFC90FDA', 16);
        $y = new PHP32("$x");

        $this->assertSame(self::getVar($x, 'value'), self::getVar($y, 'value'));
    }

    public static function getStaticClass()
    {
        return 'phpseclib3\Math\BigInteger\Engines\PHP32';
    }
}
