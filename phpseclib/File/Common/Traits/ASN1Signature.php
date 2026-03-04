<?php

/**
 * Common methods for signature algorithm identification
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\Common\Traits;

use phpseclib4\Crypt\Common\PublicKey;
use phpseclib4\Crypt\Common\PrivateKey;
use phpseclib4\Crypt\DSA;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\RSA;
use phpseclib4\Crypt\RSA\Formats\Keys\PSS;
use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\File\ASN1\Types\BitString;
use phpseclib4\File\ASN1\Types\ExplicitNull;
use phpseclib4\File\ASN1\Types\OID;

/**
 * Common methods for signature algorithm identification
 *
 * Used by X509, CSR and CRL
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
trait ASN1Signature
{
    /**
     * Identify signature algorithm from private key
     *
     * @throws UnsupportedAlgorithmException if the algorithm is unsupported
     */
    private static function identifySignatureAlgorithmHelper(PrivateKey $key): array
    {
        $hash = (string) $key->getHash();
        if ($key instanceof RSA) {
            if ($key->getPadding() & RSA::SIGNATURE_PSS) {
                $r = PSS::load($key->withPassword()->toString('PSS'));
                return [
                    'algorithm' => 'id-RSASSA-PSS',
                    'parameters' => PSS::savePSSParams($r)
                ];
            }
            switch ($hash) {
                case 'sha512/224':
                case 'sha512/256':
                    $hash = str_replace('/', '-', $hash);
                case 'md2':
                case 'md5':
                case 'sha1':
                case 'sha224':
                case 'sha256':
                case 'sha384':
                case 'sha512':
                    return [
                        'algorithm' => $hash . 'WithRSAEncryption',
                        'parameters' => new ExplicitNull(),
                    ];
            }
            throw new UnsupportedAlgorithmException('The only supported hash algorithms for RSA are: md2, md5, sha1, sha224, sha256, sha384, sha512');
        }

        if ($key instanceof DSA) {
            switch ($hash) {
                case 'sha1':
                case 'sha224':
                case 'sha256':
                    return ['algorithm' => 'id-dsa-with-' . $hash];
            }
            throw new UnsupportedAlgorithmException('The only supported hash algorithms for DSA are: sha1, sha224, sha256');
        }

        if ($key instanceof EC) {
            switch ($key->getCurve()) {
                case 'Ed25519':
                case 'Ed448':
                    return ['algorithm' => 'id-' . $key->getCurve()];
            }
            switch ($hash) {
                case 'sha1':
                case 'sha224':
                case 'sha256':
                case 'sha384':
                case 'sha512':
                    return ['algorithm' => 'ecdsa-with-' . strtoupper($hash)];
            }
            throw new UnsupportedAlgorithmException('The only supported hash algorithms for EC are: sha1, sha224, sha256, sha384, sha512');
        }

        throw new UnsupportedAlgorithmException('The only supported public key classes are: RSA, DSA, EC');
    }

    private static function validateSignatureHelper(PublicKey $key, OID|string $signatureAlgorithm, BitString $signature, string $signatureSubject)
    {
        $signatureAlgorithm = (string) $signatureAlgorithm;
        if ($key instanceof RSA) {
            switch ($signatureAlgorithm) {
                case 'id-RSASSA-PSS':
                    $key = $key->withPadding(RSA::SIGNATURE_PSS);
                    break;
                case 'md2WithRSAEncryption':
                case 'md5WithRSAEncryption':
                case 'sha1WithRSAEncryption':
                case 'sha224WithRSAEncryption':
                case 'sha256WithRSAEncryption':
                case 'sha384WithRSAEncryption':
                case 'sha512WithRSAEncryption':
                case 'sha512-224WithRSAEncryption':
                case 'sha512-256WithRSAEncryption':
                    $hash = preg_replace('#WithRSAEncryption$#', '', $signatureAlgorithm);
                    $hash = str_replace('-', '/', $hash);
                    $key = $key
                        ->withHash($hash)
                        ->withPadding(RSA::SIGNATURE_PKCS1);
                    break;
                default:
                    throw new UnsupportedAlgorithmException('Signature algorithm unsupported');
            }
        }

        if ($key instanceof DSA) {
            switch ($signatureAlgorithm) {
                case 'id-dsa-with-sha1':
                case 'id-dsa-with-sha224':
                case 'id-dsa-with-sha256':
                    $key = $key
                        ->withHash(preg_replace('#^id-dsa-with-#', '', strtolower($signatureAlgorithm)));
                    break;
                default:
                    throw new UnsupportedAlgorithmException('Signature algorithm unsupported');
            }
        }

        if ($key instanceof EC) {
            switch ($signatureAlgorithm) {
                case 'id-Ed25519':
                case 'id-Ed448':
                    break;
                case 'ecdsa-with-SHA1':
                case 'ecdsa-with-SHA224':
                case 'ecdsa-with-SHA256':
                case 'ecdsa-with-SHA384':
                case 'ecdsa-with-SHA512':
                    $key = $key
                        ->withHash(preg_replace('#^ecdsa-with-#', '', strtolower($signatureAlgorithm)));
                    break;
                default:
                    throw new UnsupportedAlgorithmException('Signature algorithm unsupported');
            }
        }

        return $key->verify($signatureSubject, substr("$signature", 1));
    }
}