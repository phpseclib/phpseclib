<?php

/**
 * Extension Helper for misc ASN1 classes
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\File\Common\Traits;

use phpseclib3\Common\Functions\Arrays;
use phpseclib3\Exception\InvalidArgumentException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Constructed;
use phpseclib3\File\ASN1\Element;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\File\ASN1\Types\BaseType;
use phpseclib3\File\ASN1\Types\Choice;
use phpseclib3\File\ASN1\Types\OctetString;
use phpseclib3\File\ASN1\Types\OID;

/**
 * Extension Helper for misc ASN1 classes
 *
 * Used by X509, CSR and CRL
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
trait Extension
{
    private static function getMapping(string $extnId): array|true|null
    {
        if (isset(self::$extensions[$extnId])) {
            return self::$extensions[$extnId];
        }

        return match ($extnId) {
            'id-ce-keyUsage' => Maps\KeyUsage::MAP,
            'id-ce-basicConstraints' => Maps\BasicConstraints::MAP,
            'id-ce-subjectKeyIdentifier' => Maps\KeyIdentifier::MAP,
            'id-ce-cRLDistributionPoints' => Maps\CRLDistributionPoints::MAP,
            'id-ce-authorityKeyIdentifier' => Maps\AuthorityKeyIdentifier::MAP,
            'id-ce-certificatePolicies' => Maps\CertificatePolicies::MAP,
            'id-ce-extKeyUsage' => Maps\ExtKeyUsageSyntax::MAP,
            // id-ce = certificate extension
            // id-pe = private extension
            'id-pe-authorityInfoAccess' => Maps\AuthorityInfoAccessSyntax::MAP,
            'id-pe-subjectInfoAccess' => Maps\SubjectInfoAccessSyntax::MAP,
            'id-ce-subjectAltName' => Maps\SubjectAltName::MAP,
            'id-ce-privateKeyUsagePeriod' => Maps\PrivateKeyUsagePeriod::MAP,
            'id-ce-issuerAltName' => Maps\IssuerAltName::MAP,
            'id-ce-policyMappings' => Maps\PolicyMappings::MAP,
            'id-ce-nameConstraints' => Maps\NameConstraints::MAP,

            // from https://datatracker.ietf.org/doc/html/rfc3739
            'id-ce-subjectDirectoryAttributes' => Maps\SubjectDirectoryAttributes::MAP,
            'id-pe-qcStatements' => Maps\QCStatements::MAP,

            'netscape-cert-type' => Maps\netscape_cert_type::MAP,
            'netscape-comment' => Maps\netscape_comment::MAP,
            'netscape-ca-policy-url' => Maps\netscape_ca_policy_url::MAP,

            // the following OIDs are unsupported but we don't want them to give notices when calling saveX509().

            'id-pe-logotype' => true, // http://www.ietf.org/rfc/rfc3709.txt
            'entrustVersInfo' => true,
            // http://support.microsoft.com/kb/287547
            '1.3.6.1.4.1.311.20.2' => true, // szOID_ENROLL_CERTTYPE_EXTENSION
            '1.3.6.1.4.1.311.21.1' => true, // szOID_CERTSRV_CA_VERSION
            // "SET Secure Electronic Transaction Specification"
            // http://www.maithean.com/docs/set_bk3.pdf
            '2.23.42.7.0' => true, // id-set-hashedRootKey
            // "Certificate Transparency"
            // https://tools.ietf.org/html/rfc6962
            '1.3.6.1.4.1.11129.2.4.2' => true,
            // "Qualified Certificate statements"
            // https://tools.ietf.org/html/rfc3739#section-3.2.6
            '1.3.6.1.5.5.7.1.3' => true,

            // CRL extensions
            // OpenSSL seems to allow these in X509 certs so i guess we will as well
            'id-ce-cRLNumber' => Maps\CRLNumber::MAP,
            'id-ce-deltaCRLIndicator' => Maps\CRLNumber::MAP,
            'id-ce-issuingDistributionPoint' => Maps\IssuingDistributionPoint::MAP,
            'id-ce-freshestCRL' => Maps\CRLDistributionPoints::MAP,
            'id-ce-cRLReasons' => Maps\CRLReason::MAP,
            'id-ce-invalidityDate' => Maps\InvalidityDate::MAP,
            'id-ce-certificateIssuer' => Maps\CertificateIssuer::MAP,
            'id-ce-holdInstructionCode' => Maps\HoldInstructionCode::MAP,

            default => null,
        };
    }

    private static function getPathToIPAddress(string $id): string
    {
        return match ($id) {
            'id-ce-subjectAltName' => '*',
            'id-ce-issuerAltName' => '*',
            'id-ce-authorityKeyIdentifier' => 'authorityCertIssuer/*',
            'id-pe-authorityInfoAccess' => '*/accessLocation',
            'id-ce-cRLDistributionPoints' => '*/cRLIssuer/*',
        };
    }

    // this NEEDS to be public so that Constructed.php can call it
    public static function mapInExtensions(Constructed $ext): void
    {
        ASN1::disableCacheInvalidation();

        $extnId = "$ext[extnId]";

        $map = self::getMapping($extnId);

        $rules = [];
        switch ($extnId) {
            case 'id-ce-certificatePolicies':
                $rules['*']['policyQualifiers']['*'] = function (Constructed $el): void {
                    if ("$el[policyQualifierId]" == 'id-qt-unotice' && $el['qualifier'] instanceof ASN1\Element) {
                        $el['qualifier'] = ASN1::map(ASN1::decodeBER($el['qualifier']->getEncoded()), Maps\UserNotice::MAP);
                    }
                    // in theory id-qt-cps maps to Maps\CPSuri::MAP but since id-qt-cps isn't a constructed type it will have
                    // already been decoded to a string by the time it gets back aroud to map() and we don't want to
                    // decode it again
                };
                break;
            // see https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
            case 'id-ce-nameConstraints':
                $rules['permittedSubtrees']['*']['base'] = $rules['excludedSubtrees']['*']['base'] = function (Choice $el): void {
                    if (isset($el['iPAddress'])) {
                        $ip = (string) $el['iPAddress'];
                        $size = strlen($ip) >> 1;
                        $mask = substr($ip, $size);
                        $ip = substr($ip, 0, $size);
                        $el['iPAddress'] = [inet_ntop($ip), inet_ntop($mask)];
                    }
                };
                break;
            // see https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
            case 'id-ce-subjectAltName':
            case 'id-ce-issuerAltName':
            case 'id-ce-authorityKeyIdentifier':
            case 'id-pe-authorityInfoAccess':
            case 'id-ce-cRLDistributionPoints':
                $path = self::getPathToIPAddress($extnId);
                $rule = &Arrays::subArray($rules, $path, true);
                // pretty much every $extnId requires Choice, save for id-pe-authorityInfoAccess,
                // which needs Constructed
                $rule = function (Choice|Constructed $el): void {
                    if (isset($el['iPAddress'])) {
                        $el['iPAddress'] = inet_ntop("$el[iPAddress]");
                    }
                };
                break;
            case 'id-pe-qcStatements':
                $rules['*'] = function (Constructed $el): void {
                    if ("$el[statementId]" == 'id-etsi-qcs-QcLimitValue' && $el['qualifier'] instanceof ASN1\Element) {
                        $el['statementInfo'] = ASN1::map(ASN1::decodeBER($el['statementInfo']->getEncoded()), Maps\QcEuLimitValue::MAP);
                    }
                };
        }

        if ($map === true) {
            $map = ['type' => ASN1::TYPE_ANY];
        }

        try {
            if (isset($map)) {
                $ext['extnValue'] = ASN1::map(ASN1::decodeBER((string) $ext['extnValue']), $map, $rules);
                if ($ext['extnValue'] instanceof Constructed) {
                    $ext['extnValue']->parent = $ext;
                    $ext['extnValue']->depth = $ext->depth + 1;
                    $ext['extnValue']->key = 'extnValue';
                }
            } else {
                $temp = ASN1::decodeBER((string) $ext['extnValue']);
                $ext['extnValue'] = is_array($temp) && $temp['content'] instanceof Constructed ?
                    new Element($ext['extnValue']->value) :
                    $temp;
            }
        } catch (\Exception $e) {
            $ext['extnValue'] = new Element($ext['extnValue']->value);
        }

        ASN1::enableCacheInvalidation();
    }

    private static function mapOutExtensionsHelper(array|Constructed &$extensions): void
    {
        $keys = is_array($extensions) ? array_keys($extensions) : $extensions->keys();
        foreach ($keys as $i) {
            switch (true) {
                case $extensions[$i] instanceof Element:
                case $extensions[$i]['extnValue'] instanceof Element:
                case $extensions[$i] instanceof Constructed && $extensions[$i]->hasEncoded():
                    continue 2;
            }

            $unparsedTest = is_array($extensions[$i]['extnValue']) && isset($extensions[$i]['extnValue']['content']);
            $unparsedTest = $unparsedTest && $extensions[$i]['extnValue']['content'] instanceof Constructed;
            $unparsedTest = $unparsedTest && !$extensions[$i]['extnValue']['content']->hasMapping();
            if ($unparsedTest) {
                $wrapping = chr(ASN1::TYPE_OCTET_STRING) . ASN1::encodeLength($extensions[$i]['extnValue']['content']->getEncodedLength());
                $extensions[$i]['extnValue']['content']->setWrapping($wrapping);
                continue;
            }

            $id = (string) $extensions[$i]['extnId'];
            $value = &$extensions[$i]['extnValue'];
            switch ($id) {
                case 'id-ce-subjectAltName':
                case 'id-ce-issuerAltName':
                case 'id-ce-authorityKeyIdentifier':
                case 'id-pe-authorityInfoAccess':
                case 'id-ce-cRLDistributionPoints':
                    $oldValue = $value instanceof Constructed ? $value->toArray() : $value;
                    $path = self::getPathToIPAddress($id);
                    Arrays::subArrayMapWithWildcards($value, $path, function (Choice|Element|array $val): Choice|Element|array {
                        if ($val instanceof Element || !isset($val['iPAddress'])) {
                            return $val;
                        }
                        return new Choice('iPAddress', new OctetString(inet_pton("$val[iPAddress]")));
                    });
                    break;
                case 'id-ce-nameConstraints':
                    $oldValue = $value instanceof Constructed ? $value->toArray() : $value;
                    $paths = ['permittedSubtrees/*/base', 'excludedSubtrees/*/base'];
                    foreach ($paths as $path) {
                        Arrays::subArrayMapWithWildcards($value, $path, function (Choice|Element|array $val): Choice|Element|array {
                            if ($val instanceof Element || !isset($val['iPAddress'])) {
                                return $val;
                            }
                            return new Choice('iPAddress', new OctetString(inet_pton($val['iPAddress'][0]) . inet_pton($val['iPAddress'][1])));
                        });
                    }
                    break;
                case 'id-ce-certificatePolicies':
                    $oldValue = $value instanceof Constructed ? $value->toArray() : $value;
                    $path = '*/policyQualifiers/*';
                    Arrays::subArrayMapWithWildcards($value, $path, function (Constructed|Element|array $val): Constructed|Element|array {
                        if ($val instanceof Element || "$val[policyQualifierId]" != 'id-qt-unotice') {
                            return $val;
                        }
                        if ($val instanceof BaseType) {
                            ASN1::encodeDER($val['qualifier'], Maps\UserNotice::MAP);
                        } else {
                            $temp = ASN1::encodeDER($val['qualifier'], Maps\UserNotice::MAP);
                            $val['qualifier'] = ASN1::map(ASN1::decodeBER($temp), Maps\UserNotice::MAP);
                        }
                        $val['qualifier']->enableForcedCache();
                        return $val;
                    });
                    break;
                case 'id-pe-qcStatements':
                    $oldValue = $value instanceof Constructed ? $value->toArray() : $value;
                    $path = '*';
                    Arrays::subArrayMapWithWildcards($value, $path, function (Choice|Element|array $val): Constructed|Element|array {
                        if ($val instanceof Element || "$val[statementId]" != 'id-etsi-qcs-QcLimitValue') {
                            return $val;
                        }
                        if ($val instanceof BaseType) {
                            ASN1::encodeDER($val['statementInfo'], Maps\QcEuLimitValue::MAP);
                        } else {
                            $temp = ASN1::encodeDER($val['statementInfo'], Maps\QcEuLimitValue::MAP);
                            $val['statementInfo'] = ASN1::map(ASN1::decodeBER($temp), Maps\QcEuLimitValue::MAP);
                        }
                        $val['statementInfo']->enableForcedCache();
                        return $val;
                    });
            }

            /* [extnValue] contains the DER encoding of an ASN.1 value
               corresponding to the extension type identified by extnID */
            $map = self::getMapping("$id");
            if ($map === true) {
                $map = ['type' => ASN1::TYPE_ANY];
            }
            if (!isset($map)) {
                //user_error($id . ' is not a currently supported extension');
                unset($extensions[$i]);
                continue;
            } else {
                if ($value instanceof BaseType) {
                    if ($value instanceof Constructed) {
                        $value->invalidateCache();
                    }
                    ASN1::encodeDER($value, $map);
                } else {
                    $temp = ASN1::encodeDER($value, $map);
                    $value = ASN1::map(ASN1::decodeBER($temp), $map);
                }
            }

            if (isset($oldValue) && $value instanceof Constructed) {
                $value->decoded = $oldValue;
            }

            $value->setWrapping(chr(ASN1::TYPE_OCTET_STRING) . ASN1::encodeLength($value->getEncodedLength()));
            $value->enableForcedCache();
        }

        if ($extensions instanceof Constructed) {
            if (count($extensions) - 1 != $extensions->lastKey()) {
                $extensions->rekey();
            }
        } else {
            if (count($extensions) - 1 != array_key_last($extensions)) {
                $extensions = array_values($extensions);
            }
        }
    }

    private static function getExtensionCriticalValue(string $name): bool
    {
        return match ($name) {
            'id-ce-keyUsage' => true,
            'id-ce-nameConstraints' => true,
            'id-ce-policyConstraints' => true,
            'id-ce-inhibitAnyPolicy' => true,

            'id-ce-authorityKeyIdentifier' => false,
            'id-ce-subjectKeyIdentifier' => false,
            'id-ce-policyMappings' => false,
            'id-ce-issuerAltName' => false,
            'id-ce-subjectDirectoryAttributes' => false,
            'id-ce-cRLDistributionPoints' => false,
            'id-ce-freshestCRL' => false,
            'id-pe-authorityInfoAccess' => false,
            'id-pe-subjectInfoAccess' => false,

            default => false
        };
    }

    private static function extensionMatch(string $search, OID|string $candidate): bool
    {
        if (is_string($candidate)) {
            $candidate = new OID($candidate);
        }
        if ($candidate->value == $search) {
            return true;
        }
        if (isset($candidate->name) && $candidate->name == $search) {
            return true;
        }
        return false;
    }
}