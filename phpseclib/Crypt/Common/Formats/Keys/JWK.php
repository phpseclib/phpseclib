<?php

/**
 * JSON Web Key (RFC7517) Handler
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\Common\Formats\Keys;

use phpseclib4\Common\Functions\Strings;

/**
 * JSON Web Key Formatted Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class JWK
{
    /**
     * Break a public or private key down into its constituent components
     *
     * @param string|array $key
     */
    protected static function loadHelper($key): \stdClass
    {
        if (!Strings::is_stringable($key)) {
            throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        $key = preg_replace('#\s#', '', $key); // remove whitespace

        $key = json_decode($key, null, 512, JSON_THROW_ON_ERROR);

        if (isset($key->kty)) {
            return $key;
        }

        if (!is_object($key)) {
            throw new \RuntimeException('invalid JWK: not an object');
        }

        if (!isset($key->keys)) {
            throw new \RuntimeException('invalid JWK: object has no property "keys"');
        }

        if (count($key->keys) != 1) {
            throw new \RuntimeException('Although the JWK key format supports multiple keys phpseclib does not');
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
