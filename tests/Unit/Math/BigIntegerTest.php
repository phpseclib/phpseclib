<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Math;

use phpseclib4\Math\BigInteger;
use phpseclib4\Tests\PhpseclibTestCase;

// the BigInteger/* tests test the individual engines but sometimes
// there can be bugs in the wrapper vs the engines
class BigIntegerTest extends PhpseclibTestCase
{
    public function testModInverse(): void
    {
        $a = new BigInteger(500);
        $b = new BigInteger(100);
        $result = $a->modInverse($b);
        $this->assertNull($result);
    }
}
