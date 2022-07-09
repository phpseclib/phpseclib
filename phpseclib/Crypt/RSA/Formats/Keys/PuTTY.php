<?php

/**
 * PuTTY Formatted RSA Key Handler
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\RSA\Formats\Keys;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\PuTTY as Progenitor;
use phpseclib3\Math\BigInteger;

/**
 * PuTTY Formatted RSA Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class PuTTY extends Progenitor
{
    /**
     * Public Handler
     *
     * @var string
     */
    public const PUBLIC_HANDLER = 'phpseclib3\Crypt\RSA\Formats\Keys\OpenSSH';

    /**
     * Algorithm Identifier
     *
     * @var array
     */
    protected static $types = ['ssh-rsa'];

    /**
     * Break a public or private key down into its constituent components
     *
     * @param array|string $key
     * @param string|false $password
     * @return array|false
     */
    public static function load($key, $password)
    {
        static $one;
        if (!isset($one)) {
            $one = new BigInteger(1);
        }

        $components = parent::load($key, $password);
        if (!isset($components['private'])) {
            return $components;
        }
        extract($components);
        unset($components['public'], $components['private']);

        $isPublicKey = false;

        $result = Strings::unpackSSH2('ii', $public);
        if ($result === false) {
            throw new \UnexpectedValueException('Key appears to be malformed');
        }
        [$publicExponent, $modulus] = $result;

        $result = Strings::unpackSSH2('iiii', $private);
        if ($result === false) {
            throw new \UnexpectedValueException('Key appears to be malformed');
        }
        $primes = $coefficients = [];
        [$privateExponent, $primes[1], $primes[2], $coefficients[2]] = $result;

        $temp = $primes[1]->subtract($one);
        $exponents = [1 => $publicExponent->modInverse($temp)];
        $temp = $primes[2]->subtract($one);
        $exponents[] = $publicExponent->modInverse($temp);

        return compact('publicExponent', 'modulus', 'privateExponent', 'primes', 'coefficients', 'exponents', 'comment', 'isPublicKey');
    }

    /**
     * Convert a private key to the appropriate format.
     */
    public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, ?string $password = null, array $options = []): string
    {
        if (count($primes) != 2) {
            throw new \InvalidArgumentException('PuTTY does not support multi-prime RSA keys');
        }

        $public =  Strings::packSSH2('ii', $e, $n);
        $private = Strings::packSSH2('iiii', $d, $primes[1], $primes[2], $coefficients[2]);

        return self::wrapPrivateKey($public, $private, 'ssh-rsa', $password, $options);
    }

    /**
     * Convert a public key to the appropriate format
     */
    public static function savePublicKey(BigInteger $n, BigInteger $e): string
    {
        return self::wrapPublicKey(Strings::packSSH2('ii', $e, $n), 'ssh-rsa');
    }
}
