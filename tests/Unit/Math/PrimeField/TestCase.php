<?php

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Math\PrimeField;

use phpseclib4\Math\BigInteger;
use phpseclib4\Math\PrimeField;
use phpseclib4\Tests\PhpseclibTestCase;

abstract class TestCase extends PhpseclibTestCase
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

    public function testPrimeFieldWithPrimeNumbers(): void
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

        $point = \phpseclib4\Crypt\EC\Formats\Keys\PKCS1::extractPoint(
            $public,
            new \phpseclib4\Crypt\EC\Curves\secp192r1()
        );

        $this->assertIsString($point[0]->toBytes());
    }

    /**
     * @group github2087
     */
    public function testZero(): void
    {
        $factory = new PrimeField(new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED', 16));
        $zero = $factory->newInteger(new BigInteger(0));
        $this->assertSame('0', "$zero");
    }
}
