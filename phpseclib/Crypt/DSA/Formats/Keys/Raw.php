<?php

/**
 * Raw DSA Key Handler
 *
 * PHP version 5
 *
 * Reads and creates arrays as DSA keys
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\DSA\Formats\Keys;

use phpseclib4\Exception\{InvalidArgumentException, UnexpectedValueException};
use phpseclib4\Math\BigInteger;

/**
 * Raw DSA Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Raw
{
    /**
     * Break a public or private key down into its constituent components
     */
    public static function load(string|array $key, #[SensitiveParameter] ?string $password = null): array
    {
        if (!is_array($key)) {
            throw new InvalidArgumentException('Key should be a array - not a string');
        }

        switch (true) {
            case !isset($key['p']) || !isset($key['q']) || !isset($key['g']):
            case !$key['p'] instanceof BigInteger:
            case !$key['q'] instanceof BigInteger:
            case !$key['g'] instanceof BigInteger:
            case !isset($key['x']) && !isset($key['y']):
            case isset($key['x']) && !$key['x'] instanceof BigInteger:
            case isset($key['y']) && !$key['y'] instanceof BigInteger:
                throw new UnexpectedValueException('Key appears to be malformed');
        }

        $options = ['p' => 1, 'q' => 1, 'g' => 1, 'x' => 1, 'y' => 1];

        return array_intersect_key($key, $options);
    }
}
