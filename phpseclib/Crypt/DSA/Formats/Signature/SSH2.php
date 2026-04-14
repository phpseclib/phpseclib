<?php

/**
 * SSH2 Signature Handler
 *
 * PHP version 5
 *
 * Handles signatures in the format used by SSH2
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\DSA\Formats\Signature;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Exception\{LengthException, UnexpectedValueException};
use phpseclib4\Math\BigInteger;

/**
 * SSH2 Signature Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class SSH2
{
    /**
     * Loads a signature
     */
    public static function load(string $sig): array
    {
        $result = Strings::unpackSSH2('ss', $sig);
        [$type, $blob] = $result;
        if ($type != 'ssh-dss' || strlen($blob) != 40) {
            throw new UnexpectedValueException('Both R and S must be less than or equal to 20 bytes in length');
        }

        return [
            'r' => new BigInteger(substr($blob, 0, 20), 256),
            's' => new BigInteger(substr($blob, 20), 256),
        ];
    }

    /**
     * Returns a signature in the appropriate format
     */
    public static function save(BigInteger $r, BigInteger $s): string
    {
        if ($r->getLength() > 160 || $s->getLength() > 160) {
            throw new LengthException('Both R and S must be less than or equal to 20 bytes in length');
        }
        return Strings::packSSH2(
            'ss',
            'ssh-dss',
            str_pad($r->toBytes(), 20, "\0", STR_PAD_LEFT) .
            str_pad($s->toBytes(), 20, "\0", STR_PAD_LEFT)
        );
    }
}
