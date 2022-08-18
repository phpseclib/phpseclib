<?php

/**
 * PKCS#8 Formatted DH Key Handler
 *
 * PHP version 5
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN ENCRYPTED PRIVATE KEY-----
 * -----BEGIN PRIVATE KEY-----
 * -----BEGIN PUBLIC KEY-----
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\DH\Formats\Keys;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\PKCS8 as Progenitor;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

/**
 * PKCS#8 Formatted DH Key Handler
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
    public const OID_NAME = 'dhKeyAgreement';

    /**
     * OID Value
     *
     * @var string
     */
    public const OID_VALUE = '1.2.840.113549.1.3.1';

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
        if (!Strings::is_stringable($key)) {
            throw new \phpseclib3\Exception\UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        $isPublic = str_contains($key, 'PUBLIC');

        $key = parent::load($key, $password);

        $type = isset($key['privateKey']) ? 'privateKey' : 'publicKey';

        switch (true) {
            case !$isPublic && $type == 'publicKey':
                throw new \phpseclib3\Exception\UnexpectedValueException('Human readable string claims non-public key but DER encoded string claims public key');
            case $isPublic && $type == 'privateKey':
                throw new \phpseclib3\Exception\UnexpectedValueException('Human readable string claims public key but DER encoded string claims private key');
        }

        $decoded = ASN1::decodeBER($key[$type . 'Algorithm']['parameters']->element);
        if (empty($decoded)) {
            throw new \phpseclib3\Exception\RuntimeException('Unable to decode BER of parameters');
        }
        $components = ASN1::asn1map($decoded[0], Maps\DHParameter::MAP);
        if (!is_array($components)) {
            throw new \phpseclib3\Exception\RuntimeException('Unable to perform ASN1 mapping on parameters');
        }

        $decoded = ASN1::decodeBER($key[$type]);
        switch (true) {
            case !isset($decoded):
            case !isset($decoded[0]['content']):
            case !$decoded[0]['content'] instanceof BigInteger:
                throw new \phpseclib3\Exception\RuntimeException('Unable to decode BER of parameters');
        }
        $components[$type] = $decoded[0]['content'];

        return $components;
    }

    /**
     * Convert a private key to the appropriate format.
     */
    public static function savePrivateKey(BigInteger $prime, BigInteger $base, BigInteger $privateKey, BigInteger $publicKey, ?string $password = null, array $options = []): string
    {
        $params = [
            'prime' => $prime,
            'base' => $base,
        ];
        $params = ASN1::encodeDER($params, Maps\DHParameter::MAP);
        $params = new ASN1\Element($params);
        $key = ASN1::encodeDER($privateKey, ['type' => ASN1::TYPE_INTEGER]);
        return self::wrapPrivateKey($key, [], $params, $password, null, '', $options);
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @param array $options optional
     */
    public static function savePublicKey(BigInteger $prime, BigInteger $base, BigInteger $publicKey, array $options = []): string
    {
        $params = [
            'prime' => $prime,
            'base' => $base,
        ];
        $params = ASN1::encodeDER($params, Maps\DHParameter::MAP);
        $params = new ASN1\Element($params);
        $key = ASN1::encodeDER($publicKey, ['type' => ASN1::TYPE_INTEGER]);
        return self::wrapPublicKey($key, $params);
    }
}
