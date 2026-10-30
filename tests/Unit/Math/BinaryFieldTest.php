<?php

/**
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib4\Tests\Unit\Math;

use phpseclib4\Math\BinaryField;
use phpseclib4\Exception\UnsupportedValueException;
use phpseclib4\Tests\PhpseclibTestCase;

class BinaryFieldTest extends PhpseclibTestCase
{
    public static function badBinaryFieldDegrees()
    {
        return [
            'exponent past the degree' => [[163, 200, 0]],
            'exponent far past the degree' => [[163, 1 << 40, 0]],
            'negative exponent' => [[163, -100000, 0]],
            'degree 0' => [[0, 0]],
            'negative degree' => [[-5, 1, 0]],
        ];
    }

    /**
     * An EC key with explicit characteristic-two parameters sets these from the key; an exponent
     * past the degree grew a string to that many bytes (an out-of-memory fatal error)
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('badBinaryFieldDegrees')]
    public function testBinaryFieldDegreesAreChecked(array $degrees)
    {
        $this->expectException(UnsupportedValueException::class);
        new BinaryField(...$degrees);
    }
}
