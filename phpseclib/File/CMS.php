<?php

/**
 * Pure-PHP CMS Parser
 *
 * PHP version 8
 *
 * Encode and decode CMS files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File;

use phpseclib4\Exception\RuntimeException;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps;

/**
 * Pure-PHP CMS Parser
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class CMS
{
    public const ISSUER_AND_DN = 1;
    public const KEY_ID = 2;
    public static bool $binary = false;

    public static function load(string $cms, int $mode = ASN1::FORMAT_AUTO_DETECT): CMS\SignedData|CMS\CompressedData|CMS\EncryptedData|CMS\DigestedData
    {
        ASN1::loadOIDs('CMS');

        if ($mode != ASN1::FORMAT_DER) {
            $newcms = ASN1::extractBER($cms);
            if ($mode == ASN1::FORMAT_PEM && $cms == $newcms) {
                throw new RuntimeException('Unable to decode PEM');
            }
            $cms = $newcms;
        }

        $pos = 0;
        $result = ASN1::decodeTag($cms, $pos);
        switch (true) {
            case !$result['constructed']:
            case $result['tag'] !== ASN1::TYPE_SEQUENCE:
            case $result['class'] !== ASN1::CLASS_UNIVERSAL:
                throw new RuntimeException('Invalid tag found (expected a universal SEQUENCE tag; found ' . ASN1::convertTypeConstantToString($result['tag']) . ')');
        }
        ASN1::decodeLength($cms, $pos);
        $result = ASN1::decodeTag($cms, $pos);
        switch (true) {
            case $result['constructed']:
            case $result['tag'] !== ASN1::TYPE_OBJECT_IDENTIFIER:
            case $result['class'] !== ASN1::CLASS_UNIVERSAL:
                throw new RuntimeException('Invalid tag found (expected a universal OID tag; found ' . ASN1::convertTypeConstantToString($result['tag']) . ')');
        }
        $length = ASN1::decodeLength($cms, $pos);
        $oid = substr($cms, $pos, $length);
        $contentType = (string) ASN1::decodeOID($oid);
        switch ($contentType) {
            case 'id-signedData':
                return CMS\SignedData::load($cms);
            case 'id-ct-compressedData':
                return CMS\CompressedData::load($cms);
            case 'id-envelopedData':
            case 'id-encryptedData':
                return CMS\EncryptedData::load($cms);
            case 'id-digestedData':
                ASN1::loadOIDs('Hashes');
                return CMS\DigestedData::load($cms);
        }
        throw new RuntimeException("$contentType is not a supported OID");
    }

    public static function createSIDRID(X509 $x509, int $type): array
    {
        switch ($type) {
            case CMS::ISSUER_AND_DN:
                return ['issuerAndSerialNumber' =>
                    [
                        'issuer' => $x509['tbsCertificate']['issuer'],
                        'serialNumber' => $x509['tbsCertificate']['serialNumber'],
                    ]
                ];
            case CMS::KEY_ID:
                $keyID = $x509->getExtension('id-ce-subjectKeyIdentifier');
                if (!isset($keyID)) {
                    throw new RuntimeException('id-ce-subjectKeyIdentifier is not present');
                }
                return ['subjectKeyIdentifier' => $keyID['extnValue']];
            default:
                throw new UnexpectedValueException('$type should be either CMS::ISSUER_AND_DN or CMS::KEY_ID');
        }
    }

    // this NEEDS to be public so that Constructed.php can call it
    public static function mapInCerts(Constructed $certs): void
    {
        ASN1::disableCacheInvalidation();
        for ($i = 0; $i < count($certs); $i++) {
            if ($certs[$i]->index != 'certificate') {
                continue;
            }
            $certs[$i]['certificate'] = X509::load((string) $certs[$i]->getEncoded());
        }
        ASN1::enableCacheInvalidation();
    }

    public static function mapInCRLs(Constructed $crls): void
    {
        ASN1::disableCacheInvalidation();
        for ($i = 0; $i < count($crls); $i++) {
            if (!isset($crls[$i]['crl'])) {
                continue;
            }
            $crls[$i] = CRL::load((string) $crls[$i]->getEncoded());
        }
        ASN1::enableCacheInvalidation();
    }

    /**
     * Enable binary output (DER)
     */
    public static function enableBinaryOutput(): void
    {
        self::$binary = true;
    }

    /**
     * Disable binary output (ie. enable PEM)
     */
    public static function disableBinaryOutput(): void
    {
        self::$binary = false;
    }
}