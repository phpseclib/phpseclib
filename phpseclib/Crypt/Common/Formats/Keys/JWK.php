<?php

/**
 * JSON Web Key (RFC7517) Handler
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\Common\Formats\Keys;

use phpseclib4\Exception\{UnexpectedValueException, UnsupportedValueException};

/**
 * JSON Web Key Formatted Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class JWK
{
    /**
     * Break a public or private key down into its constituent components
     */
    protected static function loadHelper(#[SensitiveParameter] string $key): \stdClass
    {
        $key = preg_replace('#\s#', '', $key); // remove whitespace

        $key = json_decode($key, null, 512, JSON_THROW_ON_ERROR);

        if (isset($key->kty)) {
            return $key;
        }

        if (!isset($key->keys)) {
            throw new UnexpectedValueException('Invalid JWK: object has no property "keys"');
        }

        if (count($key->keys) != 1) {
            throw new UnsupportedValueException('Although the JWK key format supports multiple keys phpseclib does not');
        }

        return $key->keys[0];
    }

    /**
     * Wrap a key appropriately
     */
    protected static function wrapKey(array $key, array $options): string
    {
        return json_encode(['keys' => [$key + $options]]);
    }
}
