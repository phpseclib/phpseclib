<?php

/**
 * PKCS#8 Formatted DSA Key Handler
 *
 * PHP version 5
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN ENCRYPTED PRIVATE KEY-----
 * -----BEGIN PRIVATE KEY-----
 * -----BEGIN PUBLIC KEY-----
 *
 * Analogous to ssh-keygen's pkcs8 format (as specified by -m). Although PKCS8
 * is specific to private keys it's basically creating a DER-encoded wrapper
 * for keys. This just extends that same concept to public keys (much like ssh-keygen)
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\DSA\Formats\Keys;

use phpseclib3\Crypt\Common\Formats\Keys\PKCS8 as Progenitor;
use phpseclib3\Exception\RuntimeException;
use phpseclib3\Exception\UnexpectedValueException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

/**
 * PKCS#8 Formatted DSA Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PKCS8 extends Progenitor
{
    /**
     * OID Name
     *
     * @var string
     */
    public const OID_NAME = 'id-dsa';

    /**
     * OID Value
     *
     * @var string
     */
    public const OID_VALUE = '1.2.840.10040.4.1';

    /**
     * Child OIDs loaded
     *
     * @var bool
     */
    protected static $childOIDsLoaded = false;

    /**
     * Break a public or private key down into its constituent components
     */
    public static function load(string|array $key, #[SensitiveParameter] ?string $password = null): array
    {
        if (!is_string($key)) {
            throw new UnexpectedValueException('Key should be a string - not an array');
        }

        if (str_contains($key, 'PUBLIC')) {
            $isPublic = true;
        } elseif (str_contains($key, 'PRIVATE')) {
            $isPublic = false;
        }

        $key = parent::load($key, $password);

        $type = isset($key['privateKey']) ? 'privateKey' : 'publicKey';

        if (isset($isPublic)) {
            switch (true) {
                case !$isPublic && $type == 'publicKey':
                    throw new UnexpectedValueException('Human readable string claims non-public key but DER encoded string claims public key');
                case $isPublic && $type == 'privateKey':
                    throw new UnexpectedValueException('Human readable string claims public key but DER encoded string claims private key');
            }
        }

        try {
            $decoded = ASN1::decodeBER((string) $key[$type . 'Algorithm']['parameters']);
            $components = ASN1::map($decoded, Maps\DSAParams::MAP)->toArray();
            $decoded = ASN1::decodeBER((string) $key[$type]);
        } catch (\Exception $e) {
            throw new RuntimeException('Unable to decode DSA key', 0, $e);
        }

        $var = $type == 'privateKey' ? 'x' : 'y';
        $components[$var] = ASN1::map($decoded, Maps\DSAPublicKey::MAP);
        if (!$components[$var] instanceof BigInteger) {
            throw new RuntimeException('Unable to perform ASN1 mapping');
        }

        if (isset($key['meta'])) {
            $components['meta'] = $key['meta'];
        }

        return $components;
    }

    /**
     * Convert a private key to the appropriate format.
     */
    public static function savePrivateKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, BigInteger $x, #[SensitiveParameter] ?string $password = null, array $options = []): string
    {
        $params = [
            'p' => $p,
            'q' => $q,
            'g' => $g,
        ];
        $params = ASN1::encodeDER($params, Maps\DSAParams::MAP);
        $params = new ASN1\Element($params);
        $key = ASN1::encodeDER($x, Maps\DSAPublicKey::MAP);
        return self::wrapPrivateKey(
            key: $key,
            params: $params,
            password: $password,
            options: $options
        );
    }

    /**
     * Convert a public key to the appropriate format
     */
    public static function savePublicKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, array $options = []): string
    {
        $params = [
            'p' => $p,
            'q' => $q,
            'g' => $g,
        ];
        $params = ASN1::encodeDER($params, Maps\DSAParams::MAP);
        $params = new ASN1\Element($params);
        $key = ASN1::encodeDER($y, Maps\DSAPublicKey::MAP);
        return self::wrapPublicKey(
            key: $key,
            params: $params,
            options: $options
        );
    }
}
