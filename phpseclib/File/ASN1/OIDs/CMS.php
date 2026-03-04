<?php

/**
 * ASN.1 CMS OIDs
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\OIDs;

/**
 * CMS OIDs
 *
 * OIDs from RFC5652
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class CMS
{
    public const OIDs = [
        'id-data' => '1.2.840.113549.1.7.1', // section 4
        'id-signedData' => '1.2.840.113549.1.7.2', // section 5
        'id-ct-compressedData' => '1.2.840.113549.1.9.16.1.9', // section 1.1
        'id-envelopedData' => '1.2.840.113549.1.7.3', // section 6
        'id-digestedData' => '1.2.840.113549.1.7.5', // section 7
        'id-encryptedData' => '1.2.840.113549.1.7.6', // section 8
        'id-ct-authData' => '1.2.840.113549.1.9.16.1.2', // section 9

        'id-contentType' => '1.2.840.113549.1.9.3', // section 11.1
        'id-messageDigest' => '1.2.840.113549.1.9.4', // section 11.2
        'id-signingTime' => '1.2.840.113549.1.9.5', // section 11.3
        'id-countersignature' => '1.2.840.113549.1.9.6', // section 11.3

        'pkcs-9-at-smimeCapabilities' => '1.2.840.113549.1.9.15', // https://tools.ietf.org/html/rfc2985

        'id-aa-signingCertificate' => '1.2.840.113549.1.9.16.2.12', // https://tools.ietf.org/html/rfc2634#section-5.4
        'id-aa-signingCertificateV2' => '1.2.840.113549.1.9.16.2.47', // https://tools.ietf.org/html/rfc5035#section-3

        'id-aa-contentIdentifier' => '1.2.840.113549.1.9.16.2.7',

        'id-alg-zlibCompress' => '1.2.840.113549.1.9.16.3.8', // from RFC3274

        // from https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.01.00_30/en_31912201v010100v.pdf
        'id-aa-ets-mimeType' => '0.4.0.1733.2.1',
        'id-aa-ets-commitmentType' => '1.2.840.113549.1.9.16.2.16',
        'id-aa-ets-signerLocation' => '1.2.840.113549.1.9.16.2.17',
        'id-aa-ets-signerAttrV2' => '0.4.0.19122.1.1',
        'id-aa-ets-claimedSAML' => '0.4.0.19122.1.2',
        'id-aa-ets-contentTimestamp' => '1.2.840.113549.1.9.16.2.20',
        'id-aa-ets-sigPolicyId' => '1.2.840.113549.1.9.16.2.15',
        'id-spq-ets-uri' => '1.2.840.113549.1.9.16.5.2',
        'id-spq-ets-docspec' => '0.4.0.19122.2.1',
        'id-aa-ets-sigPolicyStore' => '0.4.0.19122.1.3',
        'id-aa-ets-archiveTimestampV3' => '0.4.0.1733.2.4',
        'id-aa-ets-certificateRefs' => '1.2.840.113549.1.9.16.2.21',
        'id-aa-ets-certValues' => '1.2.840.113549.1.9.16.2.23',
        'id-aa-ets-revocationRefs' => '1.2.840.113549.1.9.16.2.22',
        'id-aa-ets-revocationValues' => '1.2.840.113549.1.9.16.2.24',
        'id-aa-ets-attrCertificateRefs' => '1.2.840.113549.1.9.16.2.44',
        'id-aa-ets-attrRevocationRefs' => '1.2.840.1113549.1.9.16.2.45',
        'id-aa-ets-certCRLTimestamp' => '1.2.840.113549.1.9.16.2.26',
        'id-aa-ets-escTimeStamp' => '1.2.840.113549.1.9.16.2.25',

        // from https://datatracker.ietf.org/doc/html/rfc6211
        'id-aa-CMSAlgorithmProtection' => '1.2.840.113549.1.9.52',
        // from https://www.ietf.org/rfc/rfc3161.txt
        'id-aa-timeStampToken' => '1.2.840.113549.1.9.16.2.14',
        'id-ct-TSTInfo' => '1.2.840.113549.1.9.16.1.4',

        // from https://www.rfc-editor.org/rfc/rfc2634.html
        'id-aa-receiptRequest' => '1.2.840.113549.1.9.16.2.1',
        'id-ct-receipt' => '1.2.840.113549.1.9.16.1.1',
        'id-aa-contentHint' => '1.2.840.113549.1.9.16.2.4',
        'id-aa-msgSigDigest' => '1.2.840.113549.1.9.16.2.5',
        'id-aa-contentReference' => '1.2.840.113549.1.9.16.2.10',
        'id-aa-securityLabel' => '1.2.840.113549.1.9.16.2.2',
        'id-aa-equivalentLabels' => '1.2.840.113549.1.9.16.2.9',
        'id-aa-mlExpandHistory' => '1.2.840.113549.1.9.16.2.3',

        // from https://datatracker.ietf.org/doc/html/rfc3394.html
        'id-aes128-wrap' => '2.16.840.1.101.3.4.1.5',
        'id-aes192-wrap' => '2.16.840.1.101.3.4.1.25',
        'id-aes256-wrap' => '2.16.840.1.101.3.4.1.45',

        // from https://datatracker.ietf.org/doc/html/rfc5649
        'id-aes128-wrap-pad' => '2.16.840.1.101.3.4.1.8',
        'id-aes192-wrap-pad' => '2.16.840.1.101.3.4.1.28',
        'id-aes256-wrap-pad' => '2.16.840.1.101.3.4.1.48',

        // from https://datatracker.ietf.org/doc/html/rfc2630
        'id-alg-CMS3DESwrap' => '1.2.840.113549.1.9.16.3.6',
        'id-alg-CMSRC2wrap' => '1.2.840.113549.1.9.16.3.7',

        'id-alg-PWRI-KEK' => '1.2.840.113549.1.9.16.3.9',

        // https://datatracker.ietf.org/doc/html/rfc5753?utm_source=chatgpt.com#section-7.1.4
        'dhSinglePass-stdDH-sha1kdf-scheme' => '1.3.133.16.840.63.0.2', // x9-63-scheme
        'dhSinglePass-stdDH-sha224kdf-scheme' => '1.3.132.1.11.0', // secg-scheme
        'dhSinglePass-stdDH-sha256kdf-scheme' => '1.3.132.1.11.1',
        'dhSinglePass-stdDH-sha384kdf-scheme' => '1.3.132.1.11.2',
        'dhSinglePass-stdDH-sha512kdf-scheme' => '1.3.132.1.11.3',
        'dhSinglePass-cofactorDH-sha1kdf-scheme' => '1.3.133.16.840.63.0.3',
        'dhSinglePass-cofactorDH-sha224kdf-scheme' => '1.3.132.1.14.0',
        'dhSinglePass-cofactorDH-sha256kdf-scheme' => '1.3.132.1.14.1',
        'dhSinglePass-cofactorDH-sha384kdf-scheme' => '1.3.132.1.14.2',
        'dhSinglePass-cofactorDH-sha512kdf-scheme' => '1.3.132.1.14.3',
        'mqvSinglePass-sha1kdf-scheme' => '1.3.133.16.840.63.0.16',
        'mqvSinglePass-sha224kdf-scheme' => '1.3.132.1.15.0',
        'mqvSinglePass-sha256kdf-scheme' => '1.3.132.1.15.1',
        'mqvSinglePass-sha384kdf-scheme' => '1.3.132.1.15.2',
        'mqvSinglePass-sha512kdf-scheme' => '1.3.132.1.15.3',

        // from https://www.rfc-editor.org/rfc/rfc9629.html
        'id-ori-kem' => '1.2.840.113549.1.9.16.13.3',

        // from https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.1
        'id-RSAES-OAEP' => '1.2.840.113549.1.1.7',
        'id-pSpecified' => '1.2.840.113549.1.1.9',

        // from https://datatracker.ietf.org/doc/html/rfc5083
        'id-ct-authEnvelopedData' => '1.2.840.113549.1.9.16.1.23',
        'id-aes128-CCM' => '2.16.840.1.101.3.4.1.7',
        'id-aes192-CCM' => '2.16.840.1.101.3.4.1.27',
        'id-aes256-CCM' => '2.16.840.1.101.3.4.1.47',
        'id-aes128-GCM' => '2.16.840.1.101.3.4.1.6',
        'id-aes192-GCM' => '2.16.840.1.101.3.4.1.26',
        'id-aes256-GCM' => '2.16.840.1.101.3.4.1.46',

        // from https://datatracker.ietf.org/doc/html/rfc8103
        'id-alg-AEADChaCha20Poly1305' => '1.2.840.113549.1.9.16.3.18',
    ];
}