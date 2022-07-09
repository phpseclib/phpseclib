<?php

/**
 * PublicKeyLoader
 *
 * Returns a PublicKey or PrivateKey object.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt;

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Exception\NoKeyLoadedException;
use phpseclib3\File\X509;

/**
 * PublicKeyLoader
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PublicKeyLoader
{
    /**
     * Loads a public or private key
     *
     * @param string|array $key
     */
    public static function load($key, ?string $password = null): AsymmetricKey
    {
        try {
            return EC::load($key, $password);
        } catch (NoKeyLoadedException $e) {
        }

        try {
            return RSA::load($key, $password);
        } catch (NoKeyLoadedException $e) {
        }

        try {
            return DSA::load($key, $password);
        } catch (NoKeyLoadedException $e) {
        }

        try {
            $x509 = new X509();
            $x509->loadX509($key);
            $key = $x509->getPublicKey();
            if ($key) {
                return $key;
            }
        } catch (\Exception $e) {
        }

        throw new NoKeyLoadedException('Unable to read key');
    }

    /**
     * Loads a private key
     *
     * @param string|array $key
     */
    public static function loadPrivateKey($key, ?string $password = null): PrivateKey
    {
        $key = self::load($key, $password);
        if (!$key instanceof PrivateKey) {
            throw new NoKeyLoadedException('The key that was loaded was not a private key');
        }
        return $key;
    }

    /**
     * Loads a public key
     *
     * @param string|array $key
     */
    public static function loadPublicKey($key): PublicKey
    {
        $key = self::load($key);
        if (!$key instanceof PublicKey) {
            throw new NoKeyLoadedException('The key that was loaded was not a public key');
        }
        return $key;
    }

    /**
     * Loads parameters
     *
     * @param string|array $key
     */
    public static function loadParameters($key): AsymmetricKey
    {
        $key = self::load($key);
        if (!$key instanceof PrivateKey && !$key instanceof PublicKey) {
            throw new NoKeyLoadedException('The key that was loaded was not a parameter');
        }
        return $key;
    }
}
