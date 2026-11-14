<?php

/**
 * Common methods for signature algorithm identification
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2025-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\Common\Traits;

use phpseclib4\Crypt\Common\{PrivateKey, PublicKey};
use phpseclib4\Crypt\{DSA, EC, MLDSA, RSA};
use phpseclib4\Crypt\RSA\Formats\Keys\PSS;
use phpseclib4\Exception\{UnexpectedValueException, UnsupportedAlgorithmException};
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Types\{BitString, ExplicitNull, OID};

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
        $key = $key->getPublicKey();
        $hash = (string) $key->getHash();
        if ($key instanceof RSA) {
            if ($key->getPadding() & RSA::SIGNATURE_PSS) {
                $r = PSS::load($key->toString('PSS'));
                return [
                    'algorithm' => 'id-RSASSA-PSS',
                    'parameters' => PSS::savePSSParams($r)
                ];
            }
            switch ($hash) {
                case 'sha512/224':
                case 'sha512/256':
                    $hash = str_replace('/', '-', $hash);
                    // no break
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

        if ($key instanceof MLDSA) {
            // the AlgorithmIdentifier is the id-ml-dsa-* OID alone: "The parameters of these signature
            // algorithms MUST be absent" (RFC 9881, section 3)
            return ['algorithm' => self::getMLDSASignatureAlgorithm($key)];
        }

        throw new UnsupportedAlgorithmException('The only supported public key classes are: RSA, DSA, EC, MLDSA');
    }

    /**
     * Returns the signature algorithm of an ML-DSA key (id-ml-dsa-44, id-ml-dsa-65 or id-ml-dsa-87)
     *
     * ML-DSA has no hash to pick, so the OID follows from the parameter set alone
     */
    private static function getMLDSASignatureAlgorithm(MLDSA $key): string
    {
        return 'id-' . strtolower($key->getParameterSet());
    }

    /**
     * $signatureAlgorithm is either the algorithm OID or the whole AlgorithmIdentifier. X509, CSR and CRL
     * pass the latter so that the parameters can be checked when the algorithm has rules for them.
     */
    private static function validateSignatureHelper(PublicKey $key, OID|string|array|Constructed $signatureAlgorithm, BitString $signature, string $signatureSubject)
    {
        $parameters = null;
        if (is_array($signatureAlgorithm) || $signatureAlgorithm instanceof Constructed) {
            $parameters = $signatureAlgorithm['parameters'] ?? null;
            $signatureAlgorithm = $signatureAlgorithm['algorithm'];
        }
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

        if ($key instanceof MLDSA) {
            if ($signatureAlgorithm != self::getMLDSASignatureAlgorithm($key)) {
                throw new UnsupportedAlgorithmException('Signature algorithm unsupported');
            }
            // RFC 9881, section 3
            if (isset($parameters)) {
                throw new UnexpectedValueException('The AlgorithmIdentifier of an ML-DSA signature must not have parameters');
            }
        }

        return $key->verify($signatureSubject, substr("$signature", 1));
    }
}
