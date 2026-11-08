<?php

/**
 * PKCS#8 Formatted ML-DSA Key Handler
 *
 * PHP version 8.1+
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN ENCRYPTED PRIVATE KEY-----
 * -----BEGIN PRIVATE KEY-----
 * -----BEGIN PUBLIC KEY-----
 *
 * The encoding is the one from RFC 9881. The AlgorithmIdentifier has no parameters and the
 * private key is a CHOICE between the 32-byte seed, the expanded private key or both. When saving,
 * whatever the key object has is written: the seed if the key was created or loaded from a seed,
 * the expanded key if that's all there is, and both if both are known.
 *
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\MLDSA\Formats\Keys;

use phpseclib4\Crypt\Common\Formats\Keys\PKCS8 as Progenitor;
use phpseclib4\Crypt\MLDSA;
use phpseclib4\Exception\{LengthException, UnexpectedValueException};
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\{Constructed, Maps};
use phpseclib4\File\ASN1\Types\Choice;

/**
 * PKCS#8 Formatted ML-DSA Key Handler
 *
 * @author  Adriel Cavalcante
 * @psalm-api
 */
abstract class PKCS8 extends Progenitor
{
    /**
     * OID Name
     *
     * @var array
     */
    public const OID_NAME = ['id-ml-dsa-44', 'id-ml-dsa-65', 'id-ml-dsa-87'];

    /**
     * OID Value
     *
     * @var array
     */
    public const OID_VALUE = ['2.16.840.1.101.3.4.3.17', '2.16.840.1.101.3.4.3.18', '2.16.840.1.101.3.4.3.19'];

    /**
     * Parameter set for each OID name
     */
    private const PARAMETER_SETS = [
        'id-ml-dsa-44' => 'ML-DSA-44',
        'id-ml-dsa-65' => 'ML-DSA-65',
        'id-ml-dsa-87' => 'ML-DSA-87',
    ];

    /**
     * Break a public or private key down into its constituent components
     */
    public static function load(
        #[\SensitiveParameter] string $key,
        #[\SensitiveParameter] ?string $password = null
    ): array {
        $key = parent::load($key, $password);

        $type = isset($key['privateKey']) ? 'privateKey' : 'publicKey';
        $algorithm = $key[$type . 'Algorithm'];

        // the parent only lets keys whose OID is in self::OID_NAME through
        $parameterSet = self::PARAMETER_SETS[(string) $algorithm['algorithm']];
        if (isset($algorithm['parameters'])) {
            throw new UnexpectedValueException('The AlgorithmIdentifier of a ' . $parameterSet . ' key must not have parameters');
        }

        $components = ['parameterSet' => $parameterSet];
        $sizes = MLDSA::PARAMETER_SETS[$parameterSet];

        if ($type == 'publicKey') {
            $components['publicKey'] = self::checkLength((string) $key['publicKey'], $sizes['publicKey'], 'public key');
            return $components;
        }

        $decoded = ASN1::decodeBER((string) $key['privateKey']);
        $choice = ASN1::map($decoded, Maps\MLDSAPrivateKey::MAP);
        if (!$choice instanceof Choice) {
            throw new UnexpectedValueException('Unable to decode the ML-DSA-PrivateKey CHOICE');
        }

        switch ($choice->index) {
            case 'seed':
                $components['seed'] = self::checkLength((string) $choice->value, MLDSA::SEED_LENGTH, 'seed');
                break;
            case 'expandedKey':
                $components['expandedKey'] = self::checkLength((string) $choice->value, $sizes['expandedKey'], 'expanded private key');
                break;
            default: // both
                if (!$choice->value instanceof Constructed) {
                    throw new UnexpectedValueException('The both CHOICE should be a SEQUENCE');
                }
                $both = $choice->value->toArray();
                $components['seed'] = self::checkLength((string) $both['seed'], MLDSA::SEED_LENGTH, 'seed');
                $components['expandedKey'] = self::checkLength((string) $both['expandedKey'], $sizes['expandedKey'], 'expanded private key');
        }

        if (isset($key['publicKey'])) {
            $components['publicKey'] = self::checkLength((string) $key['publicKey'], $sizes['publicKey'], 'public key');
        }

        return $components;
    }

    /**
     * Returns $value if it has the expected length and throws an exception otherwise
     */
    private static function checkLength(#[\SensitiveParameter] string $value, int $expected, string $what): string
    {
        if (strlen($value) != $expected) {
            throw new LengthException("The $what should be $expected bytes long (it's " . strlen($value) . ' bytes long)');
        }
        return $value;
    }

    /**
     * Returns the OID name of a parameter set
     */
    private static function getOID(string $parameterSet): string
    {
        $oid = array_search($parameterSet, self::PARAMETER_SETS, true);
        if ($oid === false) {
            throw new UnexpectedValueException("$parameterSet is not a supported ML-DSA parameter set");
        }
        return $oid;
    }

    /**
     * Convert a public key to the appropriate format
     */
    public static function savePublicKey(string $parameterSet, string $publicKey, array $options = []): string
    {
        self::checkLength($publicKey, MLDSA::PARAMETER_SETS[$parameterSet]['publicKey'] ?? 0, 'public key');

        return self::wrapPublicKey(
            key: $publicKey,
            params: null,
            oid: self::getOID($parameterSet),
            options: $options
        );
    }

    /**
     * Convert a private key to the appropriate format.
     */
    public static function savePrivateKey(
        string $parameterSet,
        #[\SensitiveParameter] ?string $seed,
        #[\SensitiveParameter] ?string $expandedKey,
        #[\SensitiveParameter] ?string $password = null,
        array $options = []
    ): string {
        $oid = self::getOID($parameterSet);

        if (isset($seed)) {
            self::checkLength($seed, MLDSA::SEED_LENGTH, 'seed');
        }
        if (isset($expandedKey)) {
            self::checkLength($expandedKey, MLDSA::PARAMETER_SETS[$parameterSet]['expandedKey'], 'expanded private key');
        }

        $key = match (true) {
            isset($seed) && isset($expandedKey) => ['both' => ['seed' => $seed, 'expandedKey' => $expandedKey]],
            isset($seed) => ['seed' => $seed],
            isset($expandedKey) => ['expandedKey' => $expandedKey],
            default => throw new UnexpectedValueException('Either the seed or the expanded private key is needed')
        };

        $key = ASN1::encodeDER($key, Maps\MLDSAPrivateKey::MAP);

        return self::wrapPrivateKey(
            key: $key,
            params: null,
            password: $password,
            oid: $oid,
            options: $options
        );
    }
}
