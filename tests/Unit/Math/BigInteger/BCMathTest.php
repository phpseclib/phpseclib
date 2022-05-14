<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

// declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Math\BigInteger;

use phpseclib3\Math\BigInteger\Engines\BCMath;

class BCMathTest extends TestCase
{
    public static function setUpBeforeClass()
    {
        if (!BCMath::isValidEngine()) {
            self::markTestSkipped('BCMath extension is not available.');
        }
        BCMath::setModExpEngine('DefaultEngine');
    }

    public function getInstance($x = 0, $base = 10): BCMath
    {
        return new BCMath($x, $base);
    }

    public static function getStaticClass(): string
    {
        return BCMath::class;
    }
}
