<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

// declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Math\BigInteger;

use phpseclib3\Math\BigInteger\Engines\PHP32;

class PHP32Test extends TestCase
{
    public static function setUpBeforeClass()
    {
        PHP32::setModExpEngine('DefaultEngine');
    }

    public function getInstance($x = 0, $base = 10): PHP32
    {
        return new PHP32($x, $base);
    }

    public function testInternalRepresentation()
    {
        $x = new PHP32('FFFFFFFFFFFFFFFFC90FDA', 16);
        $y = new PHP32("$x");

        $this->assertSame(self::getVar($x, 'value'), self::getVar($y, 'value'));
    }

    public static function getStaticClass(): string
    {
        return PHP32::class;
    }
}
