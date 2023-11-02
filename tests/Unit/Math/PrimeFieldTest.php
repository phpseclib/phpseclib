<?php

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Math;

use phpseclib3\Math\BigInteger;
use phpseclib3\Math\PrimeField;
use phpseclib3\Tests\PhpseclibTestCase;

class PrimeFieldTest extends PhpseclibTestCase
{
    public function testPrimeFieldWithCompositeNumbers(): void
    {
        $this->expectException('UnexpectedValueException');

        $a = new BigInteger('65', 10);
        $p = new BigInteger('126', 10); // 126 isn't a prime

        $num = new PrimeField($p);
        $num2 = $num->newInteger($a);

        $num2->squareRoot();
    }

    public function testPrimeFieldWithPrimeNumbers()
    {
        $a = new BigInteger('65', 10);
        $p = new BigInteger('127', 10);

        $num = new PrimeField($p);
        $num2 = $num->newInteger($a);

        $this->assertFalse($num2->squareRoot());
    }

    /**
     * @group github1929
     */
    public function testGarbageCollectedToBytes(): void
    {
        $blob = base64_decode('BFgsTFQeqKr0toyURbtT43INMDS7FTHjz3yn3MR1/Yv/pb2b9ZCYNQ/Tafe5hQpEJ4TpZOKfikP/hWZvFL8QCPgqbIGqw/KTfA==');
        $public = "\0" . substr($blob, 0, 49);
        $private = substr($blob, -24);

        $point = \phpseclib3\Crypt\EC\Formats\Keys\PKCS1::extractPoint(
            $public,
            new \phpseclib3\Crypt\EC\Curves\secp192r1()
        );

        $this->assertIsString($point[0]->toBytes());
    }
}
