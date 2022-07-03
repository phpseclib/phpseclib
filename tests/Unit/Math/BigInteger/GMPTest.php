<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Math\BigInteger;

use phpseclib3\Math\BigInteger\Engines\GMP;

class GMPTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!GMP::isValidEngine()) {
            self::markTestSkipped('GNU Multiple Precision (GMP) extension is not available.');
        }
        GMP::setModExpEngine('DefaultEngine');
    }

    public function getInstance($x = 0, $base = 10): GMP
    {
        return new GMP($x, $base);
    }

    public static function getStaticClass(): string
    {
        return 'phpseclib3\Math\BigInteger\Engines\GMP';
    }
}
