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
     *
     * @param string|array $key
     */
    public static function load($key, ?string $password = null): array
    {
        $key = parent::load($key, $password);

        $type = isset($key['privateKey']) ? 'privateKey' : 'publicKey';

        $decoded = ASN1::decodeBER($key[$type . 'Algorithm']['parameters']->element);
        if (!$decoded) {
            throw new RuntimeException('Unable to decode BER of parameters');
        }
        $components = ASN1::asn1map($decoded[0], Maps\DSAParams::MAP);
        if (!is_array($components)) {
            throw new RuntimeException('Unable to perform ASN1 mapping on parameters');
        }

        $decoded = ASN1::decodeBER($key[$type]);
        if (empty($decoded)) {
            throw new RuntimeException('Unable to decode BER');
        }

        $var = $type == 'privateKey' ? 'x' : 'y';
        $components[$var] = ASN1::asn1map($decoded[0], Maps\DSAPublicKey::MAP);
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
    public static function savePrivateKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, BigInteger $x, ?string $password = null, array $options = []): string
    {
        $params = [
            'p' => $p,
            'q' => $q,
            'g' => $g,
        ];
        $params = ASN1::encodeDER($params, Maps\DSAParams::MAP);
        $params = new ASN1\Element($params);
        $key = ASN1::encodeDER($x, Maps\DSAPublicKey::MAP);
        return self::wrapPrivateKey($key, [], $params, $password, null, '', $options);
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @param array $options optional
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
        return self::wrapPublicKey($key, $params);
    }
}
