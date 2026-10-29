<?php

/**
 * Raw ML-DSA Key Handler
 *
 * PHP version 8.1+
 *
 * An array with the parameter set and the raw key material, as in FIPS 204 (and as the NIST test
 * vectors give it):
 *
 * [
 *     'parameterSet' => 'ML-DSA-65',
 *     'seed' => ...,        // the 32-byte seed (xi), private keys only
 *     'expandedKey' => ..., // the expanded private key (sk), private keys only
 *     'publicKey' => ...    // the public key (pk)
 * ]
 *
 * A private key needs the seed, the expanded key or both. A public key needs the public key only.
 *
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\MLDSA\Formats\Keys;

use phpseclib4\Crypt\MLDSA;
use phpseclib4\Exception\{LengthException, UnexpectedValueException};

/**
 * Raw ML-DSA Key Handler
 *
 * @author  Adriel Cavalcante
 * @psalm-api
 */
abstract class Raw
{
    /**
     * Break a public or private key down into its constituent components
     *
     * @psalm-suppress PossiblyUnusedParam
     */
    public static function load(
        #[\SensitiveParameter] array $key,
        #[\SensitiveParameter] ?string $password = null
    ): array {
        $key = array_change_key_case($key, CASE_LOWER);

        if (!isset($key['parameterset']) || !is_string($key['parameterset'])) {
            throw new UnexpectedValueException('No parameter set present');
        }
        $parameterSet = MLDSA::getParameterSetName($key['parameterset']);
        $sizes = MLDSA::PARAMETER_SETS[$parameterSet];

        $components = ['parameterSet' => $parameterSet];

        $lengths = [
            'seed' => MLDSA::SEED_LENGTH,
            'expandedkey' => $sizes['expandedKey'],
            'publickey' => $sizes['publicKey'],
        ];
        foreach ($lengths as $index => $length) {
            if (!isset($key[$index])) {
                continue;
            }
            if (!is_string($key[$index])) {
                throw new UnexpectedValueException("$index should be a string");
            }
            if (strlen($key[$index]) != $length) {
                throw new LengthException("$index should be $length bytes long (it's " . strlen($key[$index]) . ' bytes long)');
            }
            $components[$index == 'seed' ? 'seed' : ($index == 'expandedkey' ? 'expandedKey' : 'publicKey')] = $key[$index];
        }

        if (count($components) == 1) {
            throw new UnexpectedValueException('No key material present (seed, expandedKey or publicKey is needed)');
        }

        return $components;
    }
}
