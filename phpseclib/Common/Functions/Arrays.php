<?php

/**
 * Common Array Functions
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Common\Functions;

use phpseclib4\Exception\RuntimeException;

/**
 * Common Array Functions
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Arrays
{
    /**
     * Check for validity of subarray
     *
     * This is kinda like Laravel's Arr::has() method with their dot notation
     *
     * This is intended for use in conjunction with _subArrayUnchecked(),
     * implementing the checks included in _subArray() but without copying
     * a potentially large array by passing its reference by-value to is_array().
     */
    public static function isSubArrayValid(array|\ArrayAccess $root, string $path): bool
    {
        if (!isset($root)) {
            return false;
        }

        foreach (explode('/', $path) as $i) {
            if (!isset($root)) {
                return false;
            }

            if (!isset($root[$i])) {
                return true;
            }

            $root = $root[$i];
        }

        return true;
    }

    /**
     * Get a reference to a subarray
     *
     * This variant of _subArray() does no is_array() checking,
     * so $root should be checked with _isSubArrayValid() first.
     *
     * This is here for performance reasons:
     * Passing a reference (i.e. $root) by-value (i.e. to is_array())
     * creates a copy. If $root is an especially large array, this is expensive.
     */
    public static function &subArrayUnchecked(array|\ArrayAccess &$root, string $path, bool $create = false): array|\ArrayAccess|null
    {
        $false = null;

        foreach (explode('/', $path) as $i) {
            if (!isset($root[$i])) {
                if (!$create) {
                    return $false;
                }

                $root[$i] = [];
            }

            $root = &$root[$i];
        }

        return $root;
    }

    /**
     * Get a reference to a subarray
     *
     * This is kinda like Laravel's Arr::set() / Arr::get() method with their dot notation
     * except that / is used as the component separator instead
     */
    public static function &subArray(array|\ArrayAccess|null &$root, string $path, bool $create = false): array|\ArrayAccess|null
    {
        $false = null;

        if (!isset($root)) {
            // if you do "return false" you'll get this error:
            // Notice: Only variable references should be returned by reference
            return $false;
        }

        foreach (explode('/', $path) as $i) {
            if (!isset($root)) {
                return $false;
            }

            if (!is_array($root) && !$root instanceof \ArrayAccess) {
                return $false;
            }

            if (!isset($root[$i])) {
                if (!$create) {
                    return $false;
                }

                $root[$i] = [];
            }

            $root = &$root[$i];
        }

        return $root;
    }

    public static function &subArrayWithWildcards(array|\ArrayAccess|null &$root, string $path, bool $create = false): mixed
    {
        if (!isset($root)) {
            throw new RuntimeException('root is not set');
        }

        $parts = explode('/', $path);
        foreach ($parts as $k=>$i) {
            if (!isset($root)) {
                $loc = implode('/', array_slice($parts, 0, $k));
                throw new RuntimeException("Unable to find node for $loc");
            }

            if (!is_array($root) && !$root instanceof \ArrayAccess) {
                $loc = implode('/', array_slice($parts, 0, $k));
                throw new RuntimeException("$loc isn't an array or an instance of ArrayAccess");
            }

            if ($i == '*') {
                $path = implode('/', array_slice($parts, $k + 1));
                foreach ($root as $key=>$val) {
                    if (empty($path)) {
                        return $val;
                    } else {
                        $val = &self::subArrayWithWildcards($root[$key], $path, $create);
                        return $val;
                    }
                }
                $loc = implode('/', array_slice($parts, 0, $k));
                throw new RuntimeException("$loc wasn't found");
            }

            if (!isset($root[$i])) {
                if (!$create) {
                    $loc = implode('/', array_slice($parts, 0, $k));
                    throw new RuntimeException("$loc wasn't found and the create flag wasn't set");
                }

                $root[$i] = [];
            }

            $root = &$root[$i];
        }

        return $root;
    }

    public static function subArrayMapWithWildcards(array|\ArrayAccess|null &$root, string $path, \Closure $func): void
    {
        $parts = explode('/', $path);
        foreach ($parts as $k=>$i) {
            if (!isset($root)) {
                return;
            }

            if ($i == '*') {
                $path = implode('/', array_slice($parts, $k + 1));
                foreach ($root as $key=>$val) {
                    if (empty($path)) {
                        $root[$key] = $func($val);
                    } else {
                        self::subArrayMapWithWildcards($root[$key], $path, $func);
                    }
                }
                return;
            }

            if (!isset($root[$i])) {
                return;
            }

            if ($k == count($parts) - 1) {
                $root[$i] = $func($root[$i]);
                return;
            }

            $root = &$root[$i];
        }

        throw new RuntimeException('Reached supposedly unreachable section of code');
    }
}
