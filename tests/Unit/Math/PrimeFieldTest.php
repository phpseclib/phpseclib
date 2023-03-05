<?php

namespace phpseclib3\Tests\Unit\Math;

use phpseclib3\Math\BigInteger;
use phpseclib3\Math\PrimeField;
use phpseclib3\Tests\PhpseclibTestCase;

class PrimeFieldTest extends PhpseclibTestCase
{
    public function testPrimeFieldWithCompositeNumbers()
    {
        $this->expectException('UnexpectedValueException');

        $a = new BigInteger('65', 10);
        $p = new BigInteger('126', 10); // 126 isn't a prime

        $num = new PrimeField($p);
        $num2 = $num->newInteger($a);

        echo $num2->squareRoot();
    }
}
