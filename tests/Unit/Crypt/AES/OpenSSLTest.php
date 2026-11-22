<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Unit\Crypt\AES;

class OpenSSLTest extends TestCase
{
    protected function setUp()
    {
        $this->engine = 'OpenSSL';
    }

    public static function continuousBufferCombos()
    {
        return self::withoutOFB8(parent::continuousBufferCombos());
    }

    public static function continuousBufferBatteryCombos()
    {
        return self::withoutOFB8(parent::continuousBufferBatteryCombos());
    }

    public static function continuousBufferBatteryCombosWithoutSingleCombos()
    {
        return self::withoutOFB8(parent::continuousBufferBatteryCombosWithoutSingleCombos());
    }

    /**
     * OpenSSL has no OFB8 mode, so these combos could only ever be skipped.
     */
    private static function withoutOFB8(array $combos)
    {
        return array_filter($combos, function (array $combo) {
            return !in_array('ofb8', $combo, true);
        });
    }
}
