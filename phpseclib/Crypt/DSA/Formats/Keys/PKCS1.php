<?php

/**
 * PKCS#1 Formatted DSA Key Handler
 *
 * PHP version 5
 *
 * Used by File/X509.php
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN DSA PRIVATE KEY-----
 * -----BEGIN DSA PUBLIC KEY-----
 * -----BEGIN DSA PARAMETERS-----
 *
 * Analogous to ssh-keygen's pem format (as specified by -m)
 *
 * Also, technically, PKCS1 decribes RSA but I am not aware of a formal specification for DSA.
 * The DSA private key format seems to have been adapted from the RSA private key format so
 * we're just re-using that as the name.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\DSA\Formats\Keys;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\PKCS1 as Progenitor;
use phpseclib3\Exception\RuntimeException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

/**
 * PKCS#1 Formatted DSA Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PKCS1 extends Progenitor
{
    /**
     * Break a public or private key down into its constituent components
     */
    public static function load(string|array $key, #[SensitiveParameter] ?string $password = null): array
    {
        $key = parent::loadHelper($key, $password);

        try {
            $decoded = ASN1::decodeBER($key);
        } catch (\Exception $e) {
            throw new RuntimeException('Unable to decode BER', 0, $e);
        }

        try {
            return ASN1::map($decoded, Maps\DSAParams::MAP)->toArray();
        } catch (\Exception $e) {
        }

        try {
            return ASN1::map($decoded, Maps\DSAPrivateKey::MAP)->toArray();
        } catch (\Exception $e) {
        }

        try {
            return ASN1::map($decoded, Maps\DSAPublicKey::MAP)->toArray();
        } catch (\Exception $e) {
        }

        throw new RuntimeException('Unable to perform ASN1 mapping');
    }

    /**
     * Convert DSA parameters to the appropriate format
     */
    public static function saveParameters(BigInteger $p, BigInteger $q, BigInteger $g): string
    {
        $key = [
            'p' => $p,
            'q' => $q,
            'g' => $g,
        ];

        $key = ASN1::encodeDER($key, Maps\DSAParams::MAP);

        return "-----BEGIN DSA PARAMETERS-----\r\n" .
               chunk_split(Strings::base64_encode($key), 64) .
               "-----END DSA PARAMETERS-----\r\n";
    }

    /**
     * Convert a private key to the appropriate format.
     */
    public static function savePrivateKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, BigInteger $x, #[SensitiveParameter] ?string $password = null, array $options = []): string
    {
        $key = [
            'version' => 0,
            'p' => $p,
            'q' => $q,
            'g' => $g,
            'y' => $y,
            'x' => $x,
        ];

        $key = ASN1::encodeDER($key, Maps\DSAPrivateKey::MAP);

        return self::wrapPrivateKey($key, 'DSA', $password, $options);
    }

    /**
     * Convert a public key to the appropriate format
     */
    public static function savePublicKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y): string
    {
        $key = ASN1::encodeDER($y, Maps\DSAPublicKey::MAP);

        return self::wrapPublicKey($key, 'DSA');
    }
}
