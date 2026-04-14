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

namespace phpseclib4\Crypt\EC\Formats\Signature;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Exception\{UnexpectedValueException, UnsupportedCurveException};
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
        [$type, $blob] = Strings::unpackSSH2('ss', $sig);
        switch ($type) {
            // see https://tools.ietf.org/html/rfc5656#section-3.1.2
            case 'ecdsa-sha2-nistp256':
            case 'ecdsa-sha2-nistp384':
            case 'ecdsa-sha2-nistp521':
                break;
            default:
                throw new UnexpectedValueException("Expected something matching ecdsa-sha2-nistp{256,384,521}, $type found");
        }

        $result = Strings::unpackSSH2('ii', $blob);

        return [
            'r' => $result[0],
            's' => $result[1],
        ];
    }

    /**
     * Returns a signature in the appropriate format
     *
     * @return string
     */
    public static function save(BigInteger $r, BigInteger $s, string $curve): string
    {
        $curve = match ($curve) {
            'secp256r1' => 'nistp256',
            'secp384r1' => 'nistp384',
            'secp521r1' => 'nistp521',
            default => throw new UnsupportedCurveException("The only supported curves are secp256r1, secp384r1 and secp521r1 - $curve provided")
        };

        $blob = Strings::packSSH2('ii', $r, $s);

        return Strings::packSSH2('ss', 'ecdsa-sha2-' . $curve, $blob);
    }
}
