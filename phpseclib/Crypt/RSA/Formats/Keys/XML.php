<?php

/**
 * XML Formatted RSA Key Handler
 *
 * More info:
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-RSAKeyValue
 * http://www.w3.org/TR/xkms2/#XKMS_2_0_Paragraph_269
 * http://en.wikipedia.org/wiki/XML_Signature
 * http://en.wikipedia.org/wiki/XKMS
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\RSA\Formats\Keys;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Exception\{BadConfigurationException, InvalidArgumentException, UnexpectedValueException};
use phpseclib4\Math\BigInteger;

/**
 * XML Formatted RSA Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class XML
{
    /**
     * Break a public or private key down into its constituent components
     */
    public static function load(string|array $key, #[SensitiveParameter] ?string $password = null): array
    {
        if (!is_string($key)) {
            throw new InvalidArgumentException('Key should be a string - not an array');
        }

        if (!class_exists('DOMDocument')) {
            throw new BadConfigurationException('The dom extension is not setup correctly on this system');
        }

        $components = [
            'isPublicKey' => false,
            'primes' => [],
            'exponents' => [],
            'coefficients' => [],
        ];

        $use_errors = libxml_use_internal_errors(true);

        $dom = new \DOMDocument();
        if (substr($key, 0, 5) != '<?xml') {
            $key = '<xml>' . $key . '</xml>';
        }
        if (!$dom->loadXML($key)) {
            $e = libxml_get_last_error();
            $message = 'Error loading XML - ' . $e->message;
            libxml_use_internal_errors($use_errors);
            throw new UnexpectedValueException($message, $e->code);
        }
        $xpath = new \DOMXPath($dom);
        $keys = ['modulus', 'exponent', 'p', 'q', 'dp', 'dq', 'inverseq', 'd'];
        foreach ($keys as $key) {
            // $dom->getElementsByTagName($key) is case-sensitive
            $temp = $xpath->query("//*[translate(local-name(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='$key']");
            if (!$temp->length) {
                continue;
            }
            $value = new BigInteger(Strings::base64_decode($temp->item(0)->nodeValue), 256);
            switch ($key) {
                case 'modulus':
                    $components['modulus'] = $value;
                    break;
                case 'exponent':
                    $components['publicExponent'] = $value;
                    break;
                case 'p':
                    $components['primes'][1] = $value;
                    break;
                case 'q':
                    $components['primes'][2] = $value;
                    break;
                case 'dp':
                    $components['exponents'][1] = $value;
                    break;
                case 'dq':
                    $components['exponents'][2] = $value;
                    break;
                case 'inverseq':
                    $components['coefficients'][2] = $value;
                    break;
                case 'd':
                    $components['privateExponent'] = $value;
            }
        }

        libxml_use_internal_errors($use_errors);

        foreach ($components as $key => $value) {
            if (is_array($value) && !count($value)) {
                unset($components[$key]);
            }
        }

        if (isset($components['modulus']) && isset($components['publicExponent'])) {
            if (count($components) == 3) {
                $components['isPublicKey'] = true;
            }
            return $components;
        }

        throw new UnexpectedValueException('Modulus / exponent not present');
    }

    /**
     * Convert a private key to the appropriate format.
     */
    public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, ?string $password = null): string
    {
        if (count($primes) != 2) {
            throw new InvalidArgumentException('XML does not support multi-prime RSA keys');
        }

        if (isset($password)) {
            throw new InvalidArgumentException('XML private keys do not support encryption');
        }

        return "<RSAKeyPair>\r\n" .
               '  <Modulus>' . Strings::base64_encode($n->toBytes()) . "</Modulus>\r\n" .
               '  <Exponent>' . Strings::base64_encode($e->toBytes()) . "</Exponent>\r\n" .
               '  <P>' . Strings::base64_encode($primes[1]->toBytes()) . "</P>\r\n" .
               '  <Q>' . Strings::base64_encode($primes[2]->toBytes()) . "</Q>\r\n" .
               '  <DP>' . Strings::base64_encode($exponents[1]->toBytes()) . "</DP>\r\n" .
               '  <DQ>' . Strings::base64_encode($exponents[2]->toBytes()) . "</DQ>\r\n" .
               '  <InverseQ>' . Strings::base64_encode($coefficients[2]->toBytes()) . "</InverseQ>\r\n" .
               '  <D>' . Strings::base64_encode($d->toBytes()) . "</D>\r\n" .
               '</RSAKeyPair>';
    }

    /**
     * Convert a public key to the appropriate format
     */
    public static function savePublicKey(BigInteger $n, BigInteger $e): string
    {
        return "<RSAKeyValue>\r\n" .
               '  <Modulus>' . Strings::base64_encode($n->toBytes()) . "</Modulus>\r\n" .
               '  <Exponent>' . Strings::base64_encode($e->toBytes()) . "</Exponent>\r\n" .
               '</RSAKeyValue>';
    }
}
