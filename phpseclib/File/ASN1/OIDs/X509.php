<?php

/**
 * ASN.1 X.509 OIDs
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
 * X.509 OIDs
 *
 * OIDs from RFC5280 and those RFCs mentioned in RFC5280#section-4.1.1.2
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class X509
{
    public const OIDs = [
        //'id-pkix' => '1.3.6.1.5.5.7',
        //'id-pe' => '1.3.6.1.5.5.7.1',
        //'id-qt' => '1.3.6.1.5.5.7.2',
        //'id-kp' => '1.3.6.1.5.5.7.3',
        //'id-ad' => '1.3.6.1.5.5.7.48',
        'id-qt-cps' => '1.3.6.1.5.5.7.2.1',
        'id-qt-unotice' => '1.3.6.1.5.5.7.2.2',
        'id-ad-ocsp' => '1.3.6.1.5.5.7.48.1',
        'id-ad-caIssuers' => '1.3.6.1.5.5.7.48.2',
        'id-ad-timeStamping' => '1.3.6.1.5.5.7.48.3',
        'id-ad-caRepository' => '1.3.6.1.5.5.7.48.5',
        //'id-at' => '2.5.4',
        'id-at-name' => '2.5.4.41',
        'id-at-surname' => '2.5.4.4',
        'id-at-givenName' => '2.5.4.42',
        'id-at-initials' => '2.5.4.43',
        'id-at-generationQualifier' => '2.5.4.44',
        'id-at-commonName' => '2.5.4.3',
        'id-at-localityName' => '2.5.4.7',
        'id-at-stateOrProvinceName' => '2.5.4.8',
        'id-at-organizationName' => '2.5.4.10',
        'id-at-organizationalUnitName' => '2.5.4.11',
        'id-at-title' => '2.5.4.12',
        'id-at-description' => '2.5.4.13',
        'id-at-dnQualifier' => '2.5.4.46',
        'id-at-countryName' => '2.5.4.6',
        'id-at-serialNumber' => '2.5.4.5',
        'id-at-pseudonym' => '2.5.4.65',
        'id-at-postalCode' => '2.5.4.17',
        'id-at-streetAddress' => '2.5.4.9',
        'id-at-uniqueIdentifier' => '2.5.4.45',
        'id-at-role' => '2.5.4.72',
        'id-at-postalAddress' => '2.5.4.16',
        'jurisdictionOfIncorporationCountryName' => '1.3.6.1.4.1.311.60.2.1.3',
        'jurisdictionOfIncorporationStateOrProvinceName' => '1.3.6.1.4.1.311.60.2.1.2',
        'jurisdictionLocalityName' => '1.3.6.1.4.1.311.60.2.1.1',
        'id-at-businessCategory' => '2.5.4.15',
        'id-domainComponent' => '0.9.2342.19200300.100.1.25',
        // from RFC3039
        'id-pda-dateOfBirth' => '1.3.6.1.5.5.7.9.1',
        'id-pda-placeOfBirth' => '1.3.6.1.5.5.7.9.2',
        'id-pda-gender' => '1.3.6.1.5.5.7.9.3',
        'id-pda-countyOfCitizenship' => '1.3.6.1.5.5.7.9.4',
        'id-pda-countyOfResidence' => '1.3.6.1.5.5.7.9.5',

        //'pkcs-9' => '1.2.840.113549.1.9',
        'pkcs-9-at-emailAddress' => '1.2.840.113549.1.9.1',
        //'id-ce' => '2.5.29',
        'id-ce-authorityKeyIdentifier' => '2.5.29.35',
        'id-ce-subjectKeyIdentifier' => '2.5.29.14',
        'id-ce-keyUsage' => '2.5.29.15',
        'id-ce-privateKeyUsagePeriod' => '2.5.29.16',
        'id-ce-certificatePolicies' => '2.5.29.32',
        //'anyPolicy' => '2.5.29.32.0',

        'id-ce-policyMappings' => '2.5.29.33',

        'id-ce-subjectAltName' => '2.5.29.17',
        'id-ce-issuerAltName' => '2.5.29.18',
        'id-ce-subjectDirectoryAttributes' => '2.5.29.9',
        'id-ce-basicConstraints' => '2.5.29.19',
        'id-ce-nameConstraints' => '2.5.29.30',
        'id-ce-policyConstraints' => '2.5.29.36',
        'id-ce-cRLDistributionPoints' => '2.5.29.31',
        'id-ce-extKeyUsage' => '2.5.29.37',
        //'anyExtendedKeyUsage' => '2.5.29.37.0',
        'id-kp-serverAuth' => '1.3.6.1.5.5.7.3.1',
        'id-kp-clientAuth' => '1.3.6.1.5.5.7.3.2',
        'id-kp-codeSigning' => '1.3.6.1.5.5.7.3.3',
        'id-kp-emailProtection' => '1.3.6.1.5.5.7.3.4',
        'id-kp-timeStamping' => '1.3.6.1.5.5.7.3.8',
        'id-kp-OCSPSigning' => '1.3.6.1.5.5.7.3.9',
        'id-ce-inhibitAnyPolicy' => '2.5.29.54',
        'id-ce-freshestCRL' => '2.5.29.46',
        'id-pe-authorityInfoAccess' => '1.3.6.1.5.5.7.1.1',
        'id-pe-subjectInfoAccess' => '1.3.6.1.5.5.7.1.11',
        'id-ce-cRLNumber' => '2.5.29.20',
        'id-ce-issuingDistributionPoint' => '2.5.29.28',
        'id-ce-deltaCRLIndicator' => '2.5.29.27',
        'id-ce-cRLReasons' => '2.5.29.21',
        'id-ce-certificateIssuer' => '2.5.29.29',
        'id-ce-holdInstructionCode' => '2.5.29.23',
        //'holdInstruction' => '1.2.840.10040.2',
        'id-holdinstruction-none' => '1.2.840.10040.2.1',
        'id-holdinstruction-callissuer' => '1.2.840.10040.2.2',
        'id-holdinstruction-reject' => '1.2.840.10040.2.3',
        'id-ce-invalidityDate' => '2.5.29.24',
        'id-pe-qcStatements' => '1.3.6.1.5.5.7.1.3',

        // from http://www.etsi.org/deliver/etsi_ts/101800_101899/101862/01.03.01_60/ts_101862v010301p.pdf
        'id-etsi-qcs' => '0.4.0.1862.1',
        'id-etsi-qcs-QcCompliance' => '0.4.0.1862.1.1',
        'id-etsi-qcs-QcLimitValue' => '0.4.0.1862.1.2',
        'id-etsi-qcs-QcRetentionPeriod' => '0.4.0.1862.1.3',

        'id-etsi-qcs-QcSSCD' => '0.4.0.1862.1.4',

        'rsaEncryption' => '1.2.840.113549.1.1.1',
        'md2WithRSAEncryption' => '1.2.840.113549.1.1.2',
        'md5WithRSAEncryption' => '1.2.840.113549.1.1.4',
        'sha1WithRSAEncryption' => '1.2.840.113549.1.1.5',
        'sha224WithRSAEncryption' => '1.2.840.113549.1.1.14',
        'sha256WithRSAEncryption' => '1.2.840.113549.1.1.11',
        'sha384WithRSAEncryption' => '1.2.840.113549.1.1.12',
        'sha512WithRSAEncryption' => '1.2.840.113549.1.1.13',
        // from https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.4
        'sha512-224WithRSAEncryption' => '1.2.840.113549.1.1.15',
        'sha512-256WithRSAEncryption' => '1.2.840.113549.1.1.16',

        'id-ecPublicKey' => '1.2.840.10045.2.1',
        'ecdsa-with-SHA1' => '1.2.840.10045.4.1',
        // from https://tools.ietf.org/html/rfc5758#section-3.2
        'ecdsa-with-SHA224' => '1.2.840.10045.4.3.1',
        'ecdsa-with-SHA256' => '1.2.840.10045.4.3.2',
        'ecdsa-with-SHA384' => '1.2.840.10045.4.3.3',
        'ecdsa-with-SHA512' => '1.2.840.10045.4.3.4',

        'id-dsa' => '1.2.840.10040.4.1',
        'id-dsa-with-sha1' => '1.2.840.10040.4.3',
        // from https://tools.ietf.org/html/rfc5758#section-3.1
        'id-dsa-with-sha224' => '2.16.840.1.101.3.4.3.1',
        'id-dsa-with-sha256' => '2.16.840.1.101.3.4.3.2',

        // from https://tools.ietf.org/html/rfc8410:
        'id-Ed25519' => '1.3.101.112',
        'id-Ed448' => '1.3.101.113',

        'id-RSASSA-PSS' => '1.2.840.113549.1.1.10',

        'dhKeyAgreement' => '1.2.840.113549.1.3.1',

        //'id-sha224' => '2.16.840.1.101.3.4.2.4',
        //'id-sha256' => '2.16.840.1.101.3.4.2.1',
        //'id-sha384' => '2.16.840.1.101.3.4.2.2',
        //'id-sha512' => '2.16.840.1.101.3.4.2.3',
        //'id-GostR3411-94-with-GostR3410-94' => '1.2.643.2.2.4',
        //'id-GostR3411-94-with-GostR3410-2001' => '1.2.643.2.2.3',
        //'id-GostR3410-2001' => '1.2.643.2.2.20',
        //'id-GostR3410-94' => '1.2.643.2.2.19',
        // Netscape Object Identifiers from "Netscape Certificate Extensions"
        'netscape' => '2.16.840.1.113730',
        'netscape-cert-extension' => '2.16.840.1.113730.1',
        'netscape-cert-type' => '2.16.840.1.113730.1.1',
        'netscape-comment' => '2.16.840.1.113730.1.13',
        'netscape-ca-policy-url' => '2.16.840.1.113730.1.8',
        // the following are X.509 extensions not supported by phpseclib
        'id-pe-logotype' => '1.3.6.1.5.5.7.1.12',
        'entrustVersInfo' => '1.2.840.113533.7.65.0',
        'verisignPrivate' => '2.16.840.1.113733.1.6.9',
        // for Certificate Signing Requests
        // see http://tools.ietf.org/html/rfc2985
        'pkcs-9-at-unstructuredName' => '1.2.840.113549.1.9.2', // PKCS #9 unstructured name
        'pkcs-9-at-challengePassword' => '1.2.840.113549.1.9.7', // Challenge password for certificate revocations
        'pkcs-9-at-extensionRequest' => '1.2.840.113549.1.9.14', // Certificate extension request
    ];
}