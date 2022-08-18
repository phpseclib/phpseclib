<?php

/**
 * OpenSSH Formatted RSA Key Handler
 *
 * PHP version 5
 *
 * Place in $HOME/.ssh/authorized_keys
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\RSA\Formats\Keys;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\OpenSSH as Progenitor;
use phpseclib3\Math\BigInteger;

/**
 * OpenSSH Formatted RSA Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class OpenSSH extends Progenitor
{
    /**
     * Supported Key Types
     *
     * @var array
     */
    protected static $types = ['ssh-rsa'];

    /**
     * Break a public or private key down into its constituent components
     *
     * @param string|array $key
     */
    public static function load($key, ?string $password = null): array
    {
        static $one;
        if (!isset($one)) {
            $one = new BigInteger(1);
        }

        $parsed = parent::load($key, $password);

        if (isset($parsed['paddedKey'])) {
            [$type] = Strings::unpackSSH2('s', $parsed['paddedKey']);
            if ($type != $parsed['type']) {
                throw new \phpseclib3\Exception\RuntimeException("The public and private keys are not of the same type ($type vs $parsed[type])");
            }

            $primes = $coefficients = [];

            [
                $modulus,
                $publicExponent,
                $privateExponent,
                $coefficients[2],
                $primes[1],
                $primes[2],
                $comment,
            ] = Strings::unpackSSH2('i6s', $parsed['paddedKey']);

            $temp = $primes[1]->subtract($one);
            $exponents = [1 => $publicExponent->modInverse($temp)];
            $temp = $primes[2]->subtract($one);
            $exponents[] = $publicExponent->modInverse($temp);

            $isPublicKey = false;

            return compact('publicExponent', 'modulus', 'privateExponent', 'primes', 'coefficients', 'exponents', 'comment', 'isPublicKey');
        }

        [$publicExponent, $modulus] = Strings::unpackSSH2('ii', $parsed['publicKey']);

        return [
            'isPublicKey' => true,
            'modulus' => $modulus,
            'publicExponent' => $publicExponent,
            'comment' => $parsed['comment'],
        ];
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @param array $options optional
     */
    public static function savePublicKey(BigInteger $n, BigInteger $e, array $options = []): string
    {
        $RSAPublicKey = Strings::packSSH2('sii', 'ssh-rsa', $e, $n);

        if ($options['binary'] ?? self::$binary) {
            return $RSAPublicKey;
        }

        $comment = $options['comment'] ?? self::$comment;
        $RSAPublicKey = 'ssh-rsa ' . base64_encode($RSAPublicKey) . ' ' . $comment;

        return $RSAPublicKey;
    }

    /**
     * Convert a private key to the appropriate format.
     */
    public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, ?string $password = null, array $options = []): string
    {
        $publicKey = self::savePublicKey($n, $e, ['binary' => true]);
        $privateKey = Strings::packSSH2('si6', 'ssh-rsa', $n, $e, $d, $coefficients[2], $primes[1], $primes[2]);

        return self::wrapPrivateKey($publicKey, $privateKey, $password, $options);
    }
}
