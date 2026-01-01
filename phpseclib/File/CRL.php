<?php

/**
 * Pure-PHP CRL Parser
 *
 * PHP version 8
 *
 * Encode and decode Certificate Revocation Lists (CRL).
 *
 * The extensions are from {@link http://tools.ietf.org/html/rfc5280 RFC5280} and
 * {@link http://web.archive.org/web/19961027104704/http://www3.netscape.com/eng/security/cert-exts.html Netscape Certificate Extensions}.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File;

use phpseclib4\Common\Functions\Arrays;
use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\Common\PrivateKey;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Element;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\ASN1\Maps\CRLReason;
use phpseclib4\File\ASN1\Types\BitString;
use phpseclib4\File\ASN1\Types\GeneralizedTime;
use phpseclib4\File\ASN1\Types\OctetString;
use phpseclib4\File\ASN1\Types\UTCTime;
use phpseclib4\File\Common\Signable;
use phpseclib4\Math\BigInteger;

/**
 * Pure-PHP CRL Parser
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class CRL implements \ArrayAccess, \Countable, \Iterator, Signable
{
    use \phpseclib4\File\Common\Traits\Extension;
    use \phpseclib4\File\Common\Traits\DN;
    use \phpseclib4\File\Common\Traits\ASN1Signature;

    private Constructed|array $crl;

    /**
     * Binary key flag
     */
    private static bool $binary = false;

    public function __construct()
    {
        ASN1::loadOIDs('X509');

        $date = new \DateTimeImmutable('now', new \DateTimeZone(@date_default_timezone_get()));

        $this->crl = [
            'tbsCertList' => [
                'version' => 'v2',
                'signature' => ['algorithm' => '0.0'],
                'issuer' => ['rdnSequence' => []],
                'thisUpdate' => ['utcTime' => $date->format('Y-m-d H:i:s')],
            ],
            'signatureAlgorithm' => [
                'algorithm' => '0.0',
            ],
            'signature' => "\0",
        ];
    }

    public static function load(string|array|Constructed $crl, int $mode = ASN1::FORMAT_AUTO_DETECT): CRL
    {
        $new = new self();
        $new->crl = is_string($crl) ? self::loadString($crl, $mode) : $crl;
        return $new;
    }

    private static function loadString(string $crl, int $mode): Constructed
    {
        if ($mode != ASN1::FORMAT_DER) {
            $newcrl = ASN1::extractBER($crl);
            if ($mode == ASN1::FORMAT_PEM && $crl == $newcrl) {
                throw new RuntimeException('Unable to decode PEM');
            }
            $crl = $newcrl;
        }

        $decoded = ASN1::decodeBER($crl);

        $rules = [];
        $rules['tbsCertList']['issuer']['rdnSequence']['*']['*'] = [self::class, 'mapInDNs'];
        $rules['tbsCertList']['crlExtensions']['*'] = [self::class, 'mapInExtensions'];
        $rules['tbsCertList']['revokedCertificates']['*']['crlEntryExtensions']['*'] = [self::class, 'mapInExtensions'];

        return ASN1::map($decoded, Maps\CertificateList::MAP, $rules);
    }

    public function __debugInfo(): array
    {
        $this->compile();
        return $this->crl->__debugInfo();
    }

    public function keys(): array
    {
        return $this->crl instanceof Constructed ? $this->crl->keys() : array_keys($this->crl);
    }

    public function &offsetGet(mixed $offset): mixed
    {
        $this->compile();
        return $this->crl[$offset];
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->crl[$offset]);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->crl[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->crl[$offset]);
    }

    public function getDNProps(string $propName): array
    {
        return $this->getIssuerDNProps($propName);
    }

    public function hasDNProp(string $propName): bool
    {
        return $this->hasIssuerNProp($propName);
    }

    public function getDN(int $format = self::DN_STRING): array|string
    {
        return $this->getIssuerDN($format);
    }

    public function setDN(array|string|Element $props): void
    {
        $this->setIssuerDN($props);
    }

    public function resetDN(): void
    {
        self::resetIssuerDN();
    }

    public function hasIssuerDNProp(string $propName): bool
    {
        return static::hasDNPropsInternal($this->crl['tbsCertList']['issuer'], $propName);
    }

    public function getIssuerDNProps(string $propName): array
    {
        return self::retrieveDNProps($this->crl['tbsCertList']['issuer'], $propName);
    }

    public function getIssuerDN(int $format = self::DN_STRING): array|string
    {
        return self::formatDN($this->crl['tbsCertList']['issuer'], $format);
    }

    public function setIssuerDN(array|string|Element $props): void
    {
        self::setDNInternal($this->crl['tbsCertList']['issuer'], $props);
    }

    public function resetIssuerDN(): void
    {
        self::setDNInternal($this->crl['tbsCertList']['issuer'], []);
    }

    public function isRevoked(BigInteger|X509 $sn): bool
    {
        $idx = $this->getRevokedIndex($sn);
        return isset($idx);
    }

    public function getRevokedInfo(BigInteger|X509 $sn): ?array
    {
        $this->compile();
        $idx = $this->getRevokedIndex($sn);
        return isset($idx) ? $this->crl['tbsCertList']['revokedCertificates'][$idx]->toArray() : null;
    }

    public function getRevokedIndex(BigInteger|X509 $sn): ?int
    {
        if ($sn instanceof X509) {
            $sn = $sn['tbsCertificate']['serialNumber'];
        }
        $list = &$this->crl['tbsCertList']['revokedCertificates'];
        $total = count($list);
        for ($i = 0; $i < $total; $i++) {
            if ($list[$i]['userCertificate']->equals($sn)) {
                unset($list[$i]->decoded);
                return $i;
            }
            unset($list[$i]->decoded);
        }
        return null;
    }

    public function getRevokedAsArray(): array
    {
        $result = [];
        $list = &$this->crl['tbsCertList']['revokedCertificates'];
        $total = count($list);
        for ($i = 0; $i < $total; $i++) {
            $temp = ['revocationDate' => (string) $list[$i]['revocationDate']];
            if (isset($list[$i]['crlEntryExtensions'])) {
                foreach ($list[$i]['crlEntryExtensions'] as $entry) {
                    if ($entry['extnId'] == 'id-ce-cRLReasons') {
                        $temp['reason'] = (string) $entry['extnValue'];
                        break;
                    }
                }
            }
            $hex = $list[$i]['userCertificate']->toHex();
            if (!isset($result[$hex])) {
                $result[$hex] = $temp;
            } else {
                if (isset($result[$hex]['revocationDate'])) {
                    $result[$hex] = [$result[$hex]];
                }
                $result[$hex][] = $temp;
            }
            unset($list[$i]->decoded);
        }
        return $result;
    }

    public function numRevoked(): int
    {
        return count($this->crl['tbsCertList']['revokedCertificates']);
    }

    public function getRevokedByIndex(int $idx): ?array
    {
        $this->compile();
        return $this->crl['tbsCertList']['revokedCertificates'][$idx]?->toArray() ?? null;
    }

    public function revoke(BigInteger|X509 $cert, ?string $reason = null, \DateTimeInterface|string|null $date = null): void
    {
        static $validReasons;
        if (!isset($validReasons)) {
            $validReasons = [];
            foreach (self::listValidRevocationReasons() as $subreason) {
                $validReasons[strtolower($subreason)] = $subreason;
            }
        }
        $temp = [];
        $temp['userCertificate'] = $cert instanceof X509 ? $cert['tbsCertificate']['serialNumber'] : $cert;
        $temp['revocationDate'] = ASN1::formatTime($date ?? 'now');
        if (isset($reason)) {
            $lower = strtolower($reason);
            if (!isset($validReasons[$lower])) {
                throw new RuntimeException('Invalid reason presented - call CRL::listValidRevocationReasons() to see a list of valid reasons');
            }
            $temp['crlEntryExtensions'][] = [
                'extnId' => 'id-ce-cRLReasons',
                'critical' => false,
                'extnValue' => $validReasons[$lower],
            ];
        }

        $this->crl['tbsCertList']['revokedCertificates'][] = $temp;
    }

    // returns true if the cert you're trying to revoke is in the cert
    // and false if it's not
    public function unrevoke(BigInteger|X509 $cert): bool
    {
        $idx = $this->getRevokedIndex($cert);
        if (!isset($idx)) {
            return false;
        }
        unset($this->crl['tbsCertList']['revokedCertificates'][$idx]);
        return true;
    }

    /**
     * Alias for setThisDate
     */
    public function setLastDate(\DateTimeInterface|string $date): void
    {
        $this->setThisDate($date);
    }

    /**
     * Set this date
     */
    public function setThisDate(\DateTimeInterface|string $date): void
    {
        $this->crl['tbsCertList']['thisUpdate'] = ASN1::formatTime($date);
    }

    /**
     * Set next date
     */
    public function setNextDate(\DateTimeInterface|string $date): void
    {
        $this->crl['tbsCertList']['nextUpdate'] = ASN1::formatTime($date);
    }

    public static function listValidRevocationReasons(): array
    {
        return array_values(CRLReason::MAP['mapping']);
    }

    public function toArray(bool $convertPrimitives = false): array
    {
        $this->compile();
        return $this->crl instanceof Constructed ? $this->crl->toArray($convertPrimitives) : $this->crl;
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

    public function __toString(): string
    {
        $this->mapOutDNs();
        $this->mapOutExtensions();

        $crl = ASN1::encodeDER($this->crl, Maps\CertificateList::MAP);

        if (self::$binary) {
            return $crl;
        }

        return "-----BEGIN X509 CRL-----\r\n" . chunk_split(Strings::base64_encode($crl), 64) . '-----END X509 CRL-----';
    }

    private function mapOutDNs(): void
    {
        $dns = &Arrays::subArray($this->crl, 'tbsCertList/issuer/rdnSequence');
        if (!$dns) {
            return;
        }

        self::mapOutDNsInner($dns);
    }

    private function mapOutExtensions(): void
    {
        $extensions = &Arrays::subArray($this->crl, 'tbsCertList/crlExtensions');
        if ($extensions) {
            self::mapOutExtensionsHelper($extensions);
        }
        $rclist = &Arrays::subArray($this->crl, 'tbsCertList/revokedCertificates');
        if ($rclist) {
            foreach ($rclist as $i => $extension) {
                $extension = &Arrays::subArray($rclist, "$i/crlEntryExtensions");
                if ($extension) {
                    self::mapOutExtensionsHelper($extension);
                }
                unset($extension);
            }
        }
    }

    private function compile(): void
    {
        if (!$this->crl instanceof Constructed) {
            $temp = self::load("$this");
            $this->crl = $temp->crl;
        }
        if ($this->crl->hasEncoded()) {
            return;
        }
        $temp = self::load("$this");
        $this->crl = $temp->crl;
    }

    public function getSignableSection(): string
    {
        $this->compile();
        return $this->crl['tbsCertList']->getEncoded();
    }

    public function setSignature(string $signature): void
    {
        $this->crl['signature'] = new BitString("\0$signature");
    }

    public function setSignatureAlgorithm(array $algorithm): void
    {
        $this->crl['tbsCertList']['signature'] = $algorithm;
        $this->crl['signatureAlgorithm'] = $algorithm;
    }

    /**
     * Identify signature algorithm from private key
     *
     * @throws UnsupportedAlgorithmException if the algorithm is unsupported
     */
    public static function identifySignatureAlgorithm(PrivateKey $key): array
    {
        return self::identifySignatureAlgorithmHelper($key);
    }

    public function setAuthorityKeyIdentifier(string|OctetString $value): void
    {
        if (is_string($value)) {
            $value = new OctetString($value);
        }
        $this->setExtension('id-ce-authorityKeyIdentifier', [
            //'authorityCertIssuer' => [
            //    [
            //        'directoryName' => $issuer['tbsCertificate']['subject']
            //    ]
            //],
            //'authorityCertSerialNumber' => $issuer['tbsCertificate']['serialNumber'],
            'keyIdentifier' => $value,
        ]);
    }

    public function listExtensions(): array
    {
        if (!isset($this->crl['tbsCertList']['crlExtensions'])) {
            return [];
        }
        $exts = [];
        foreach ($this->crl['tbsCertList']['crlExtensions'] as $ext) {
            $exts[] = (string) $ext['extnId'];
        }
        return $exts;
    }

    public function listRevokedExtensions(BigInteger|X509 $cert): array
    {
        $r = $this->getRevokedInfo($cert);
        if (!isset($r) || !isset($r['crlEntryExtensions'])) {
            return [];
        }
        $exts = [];
        foreach ($r['crlEntryExtensions'] as $ext) {
            $exts[] = (string) $ext['extnId'];
        }
        return $exts;
    }

    // returns the first instance of an extension even if there are multiple instances
    // or null if said extension isn't present
    public function getExtension(string $name): ?array
    {
        $this->compile();
        if (!isset($this->crl['tbsCertList']['crlExtensions'])) {
            return null;
        }
        foreach ($this->crl['tbsCertList']['crlExtensions'] as $ext) {
            if (self::extensionMatch($name, $ext['extnId'])) {
                return [
                    'extnId' => $name,
                    'extnValue' => $ext['extnValue'],
                    'critical' => is_bool($ext['critical']) ? $ext['critical'] : $ext['critical']->value
                ];
            }
        }
        return null;
    }

    // returns the first instance of an extension even if there are multiple instances
    // or null if said extension isn't present
    public function getRevokedExtension(BigInteger|X509 $cert, string $name): ?array
    {
        $this->compile();
        $r = $this->getRevokedInfo($cert);
        if (!isset($r) || !isset($r['crlEntryExtensions'])) {
            return null;
        }
        foreach ($r['crlEntryExtensions'] as $ext) {
            if (self::extensionMatch($name, $ext['extnId'])) {
                return [
                    'extnId' => $ext['extnId'],
                    'extnValue' => $ext['extnValue'],
                    'critical' => is_bool($ext['critical']) ? $ext['critical'] : $ext['critical']->value
                ];
            }
        }
        return null;
    }

    public function hasExtension(string $name): bool
    {
        if (!isset($this->crl['tbsCertificate']['crlExtensions'])) {
            return false;
        }
        foreach ($this->crl['tbsCertificate']['crlExtensions'] as $ext) {
            if ("$ext[extnId]" == $name) {
                return true;
            }
        }
        return false;
    }

    public function hasRevokedExtension(BigInteger|X509 $cert, string $name): bool
    {
        $r = $this->getRevokedInfo($cert);
        if (!isset($r) || !isset($r['crlEntryExtensions'])) {
            return false;
        }
        foreach ($r['crlEntryExtensions'] as $ext) {
            if ("$ext[extnId]" == $name) {
                return true;
            }
        }
        return false;
    }

    public function removeExtension(string $name): void
    {
        if (!isset($this->crl['tbsCertList']['crlExtensions'])) {
            return;
        }
        foreach ($this->crl['tbsCertList']['crlExtensions'] as $i => $ext) {
            if ("$ext[extnId]" == $name) {
                unset($this->crl['tbsCertList']['crlExtensions'][$i]);
            }
        }
    }

    public function removeRevokedExtension(BigInteger|X509 $cert, string $name): void
    {
        $idx = $this->getRevokedIndex($cert);
        if (!isset($idx)) {
            return;
        }
        $revoked = &$this->crl['tbsCertList']['revokedCertificates'][$idx];
        if (!isset($revoked['crlEntryExtensions'])) {
            return;
        }
        foreach ($revoked['crlEntryExtensions'] as $i => $ext) {
            if ("$ext[extnId]" == $name) {
                unset($revoked['crlEntryExtensions'][$i]);
            }
        }
    }

    // $value could be array|Constructed|Element|BaseType|int|float|bool|string|null
    // and by array that means any of the non-array types in any combination. eg.
    // [Constructed, int] would be sufficient as would [array, BaseType]
    public function setExtension(string $name, mixed $value, ?bool $critical = null): void
    {
        $origCritical = $critical;
        if (!isset($critical)) {
            $critical = self::getExtensionCriticalValue($name);
        }
        if (isset($this->crl['tbsCertList']['crlExtensions'])) {
            foreach ($this->crl['tbsCertList']['crlExtensions'] as $i => $ext) {
                $ext = &$this->crl['tbsCertList']['crlExtensions'][$i];
                if ("$ext[extnId]" == $name) {
                    $ext['extnValue'] = $value;
                    if (isset($origCritical)) {
                        $ext['critical'] = $origCritical;
                    }
                    return;
                }
                unset($ext);
            }
        } else {
            $this->crl['tbsCertList']['crlExtensions'] = [];
        }

        $this->crl['tbsCertList']['crlExtensions'][] = [
            'extnId' => $name,
            'critical' => $critical,
            'extnValue' => $value,
        ];
    }

    // $value could be array|Constructed|Element|BaseType|int|float|bool|string|null
    // and by array that means any of the non-array types in any combination. eg.
    // [Constructed, int] would be sufficient as would [array, BaseType]
    // if $cert doesn't exist in the CRL this will *not* add it. if you want to revoke
    // a new cert call revoke().
    // if an extension is present multiple times only the first instance will be updated
    public function setRevokedExtension(BigInteger|X509 $cert, string $name, mixed $value, ?bool $critical = null): void
    {
        $idx = $this->getRevokedIndex($cert);
        if (!isset($idx)) {
            return;
        }
        $origCritical = $critical;
        if (!isset($critical)) {
            $critical = self::getExtensionCriticalValue($name);
        }
        $revoked = &$this->crl['tbsCertList']['revokedCertificates'][$idx];
        if (!isset($revoked['crlEntryExtensions'])) {
            $revoked['crlEntryExtensions'][] = [
                'extnId' => $name,
                'critical' => $critical,
                'extnValue' => $value,
            ];
            return;
        }
        foreach ($revoked['crlEntryExtensions'] as $i=>$ext) {
            $ext = &$revoked['crlEntryExtensions'][$i];
            if ("$ext[extnId]" == $name) {
                $ext['extnValue'] = $value;
                if (isset($origCritical)) {
                    $ext['critical'] = $origCritical;
                }
                return;
            }
        }
        unset($ext);
        $revoked['crlEntryExtensions'][] = [
            'extnId' => $name,
            'critical' => $critical,
            'extnValue' => $value,
        ];
    }

    public function count(): int
    {
        return is_array($this->crl) ? count($this->crl) : $this->crl->count();
    }

    public function rewind(): void
    {
        $this->compile();
        $this->crl->rewind();
    }

    public function current(): mixed
    {
        $this->compile();
        return $this->crl->current();
    }

    public function key(): mixed
    {
        $this->compile();
        return $this->crl->key();
    }

    public function next(): void
    {
        $this->compile();
        $this->crl->next();
    }

    public function valid(): bool
    {
        $this->compile();
        return $this->crl->valid();
    }

    /**
     * Validate a signature
     *
     * Returns true if the signature is verified, false if it is not correct or on error
     *
     * The behavior of this function is inspired by {@link http://php.net/openssl-verify openssl_verify}.
     */
    public function validateSignature(): bool
    {
        $CAs = X509::getCAs();
        foreach ($CAs as $i=>$ca) {
            if ($ca->isIssuerOf($this)) {
                $signingCert = $ca;
                break;
            }
        }
        if (!isset($signingCert)) {
            return false;
        }
        $this->compile();
        return self::validateSignatureHelper(
            $signingCert->getPublicKey(),
            $this->crl['signatureAlgorithm']['algorithm'],
            $this->crl['signature'],
            $this->crl['tbsCertList']->getEncoded()
        );
    }

    public function getEncoded(): string
    {
        $this->compile();
        return $this->crl->getEncoded();
    }
}