<?php

/**
 * @author    phpseclib contributors
 * @copyright 2026 phpseclib contributors
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Common\Functions;

use phpseclib4\Common\Functions\Arrays;
use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\Tests\PhpseclibTestCase;

class ArraysTest extends PhpseclibTestCase
{
    public function testSubArrayReturnsNullForNullArrayAccessChild(): void
    {
        $root = new NullArrayAccessChild();

        $result = &Arrays::subArray($root, 'a/b');

        $this->assertNull($result);
    }

    public function testSubArrayWithWildcardsReportsMissingNullChild(): void
    {
        $root = new NullArrayAccessChild();

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Unable to find node for a');

        Arrays::subArrayWithWildcards($root, 'a/b');
    }
}
