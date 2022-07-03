<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Math\BigInteger;

use phpseclib3\Math\BigInteger;

class DefaultTest extends TestCase
{
    public function getInstance($x = 0, $base = 10): BigInteger
    {
        return new BigInteger($x, $base);
    }

    public static function getStaticClass(): string
    {
        return 'phpseclib3\Math\BigInteger';
    }
}
