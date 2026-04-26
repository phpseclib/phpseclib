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

namespace phpseclib4\Crypt;

use phpseclib4\Crypt\Common\{AsymmetricKey, PrivateKey, PublicKey};
use phpseclib4\Exception\NoKeyLoadedException;
use phpseclib4\File\{ASN1, X509};

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
     * @throws NoKeyLoadedException if key is not valid
     */
    public static function load(
        #[SensitiveParameter] string|array $key,
        #[SensitiveParameter] ?string $password = null
    ): AsymmetricKey {
        // use ASN1::EXCEPTIONS_EVERY_TIME here because without it a valid RSAPublicKey
        // will be recognized as an invalid RSAPrivateKey
        $reenable = ASN1::isBlobsOnBadDecodesEnabled();
        ASN1::disableBlobsOnBadDecodes();
        try {
            $key = EC::load($key, $password);
            if ($reenable) {
                ASN1::enableBlobsOnBadDecodes();
            }
            return $key;
        } catch (NoKeyLoadedException) {
        }

        try {
            $key = RSA::load($key, $password);
            if ($reenable) {
                ASN1::enableBlobsOnBadDecodes();
            }
            return $key;
        } catch (NoKeyLoadedException) {
        }

        try {
            $key = DSA::load($key, $password);
            if ($reenable) {
                ASN1::enableBlobsOnBadDecodes();
            }
            return $key;
        } catch (NoKeyLoadedException) {
        }

        try {
            $key = X509::load($key)->getPublicKey();
            if ($reenable) {
                ASN1::enableBlobsOnBadDecodes();
            }
            return $key;
        } catch (\Exception) {
        }

        if ($reenable) {
            ASN1::enableBlobsOnBadDecodes();
        }

        throw new NoKeyLoadedException('Unable to read key');
    }

    /**
     * Loads a private key
     */
    public static function loadPrivateKey(
        #[SensitiveParameter] string|array $key,
        #[SensitiveParameter] ?string $password = null
    ): PrivateKey {
        $key = self::load($key, $password);
        if (!$key instanceof PrivateKey) {
            throw new NoKeyLoadedException('The key that was loaded was not a private key');
        }
        return $key;
    }

    /**
     * Loads a public key
     */
    public static function loadPublicKey(string|array $key): PublicKey
    {
        $key = self::load($key);
        if (!$key instanceof PublicKey) {
            throw new NoKeyLoadedException('The key that was loaded was not a public key');
        }
        return $key;
    }

    /**
     * Loads parameters
     */
    public static function loadParameters(string $key): AsymmetricKey
    {
        $key = self::load($key);
        if (!$key instanceof PrivateKey && !$key instanceof PublicKey) {
            throw new NoKeyLoadedException('The key that was loaded was not a parameter');
        }
        return $key;
    }
}
