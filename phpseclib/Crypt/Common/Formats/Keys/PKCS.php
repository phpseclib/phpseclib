<?php

/**
 * PKCS Formatted Key Handler
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\Common\Formats\Keys;

/**
 * PKCS1 Formatted Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PKCS
{
    /**
     * Auto-detect the format
     */
    public const MODE_ANY = 0;
    /**
     * Require base64-encoded PEM's be supplied
     */
    public const MODE_PEM = 1;
    /**
     * Require raw DER's be supplied
     */
    public const MODE_DER = 2;
    /**#@-*/

    /**
     * Is the key a base-64 encoded PEM, DER or should it be auto-detected?
     */
    protected static int $format = self::MODE_ANY;

    /**
     * Require base64-encoded PEM's be supplied
     */
    public static function requirePEM(): void
    {
        self::$format = self::MODE_PEM;
    }

    /**
     * Require raw DER's be supplied
     */
    public static function requireDER(): void
    {
        self::$format = self::MODE_DER;
    }

    /**
     * Accept any format and auto detect the format
     *
     * This is the default setting
     */
    public static function requireAny(): void
    {
        self::$format = self::MODE_ANY;
    }
}
