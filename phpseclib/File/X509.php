<?php

/**
 * Pure-PHP X.509 Parser
 *
 * PHP version 8
 *
 * Encode and decode X.509 certificates.
 *
 * The extensions are from {@link http://tools.ietf.org/html/rfc5280 RFC5280} and
 * {@link http://web.archive.org/web/19961027104704/http://www3.netscape.com/eng/security/cert-exts.html Netscape Certificate Extensions}.
 *
 * Note that loading an X.509 certificate and resaving it may invalidate the signature.  The reason being that the signature is based on a
 * portion of the certificate that contains optional parameters with default values.  ie. if the parameter isn't there the default value is
 * used.  Problem is, if the parameter is there and it just so happens to have the default value there are two ways that that parameter can
 * be encoded.  It can be encoded explicitly or left out all together.  This would effect the signature value and thus may invalidate the
 * the certificate all together unless the certificate is re-signed.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\File;

use phpseclib3\Common\Functions\Arrays;
use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\Hash;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\Random;
use phpseclib3\Crypt\RSA;
use phpseclib3\Exception\CharacterConversionException;
use phpseclib3\Exception\InvalidArgumentException;
use phpseclib3\Exception\MethodOnlyAvailableForSelfSigned;
use phpseclib3\Exception\NoKeyLoadedException;
use phpseclib3\Exception\RuntimeException;
use phpseclib3\Exception\UnsupportedFormatException;
use phpseclib3\File\ASN1\Constructed;
use phpseclib3\File\ASN1\Element;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\File\ASN1\Types\BaseString;
use phpseclib3\File\ASN1\Types\BaseType;
use phpseclib3\File\ASN1\Types\BitString;
use phpseclib3\File\ASN1\Types\Boolean;
use phpseclib3\File\ASN1\Types\Choice;
use phpseclib3\File\ASN1\Types\ExplicitNull;
use phpseclib3\File\ASN1\Types\GeneralizedTime;
use phpseclib3\File\ASN1\Types\OctetString;
use phpseclib3\File\ASN1\Types\OID;
use phpseclib3\File\ASN1\Types\UTCTime;
use phpseclib3\File\ASN1\Types\UTF8String;
use phpseclib3\File\Common\Signable;
use phpseclib3\Math\BigInteger;

/**
 * Pure-PHP X.509 Parser
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class X509 implements \ArrayAccess, \Countable, \Iterator, Signable
{
    use \phpseclib3\File\Common\Traits\Extension;
    use \phpseclib3\File\Common\Traits\DN;
    use \phpseclib3\File\Common\Traits\ASN1Signature;

    private Constructed|array $cert;
    private static bool $strictDNComparison = true;
    public ?self $issuer = null;
    private static \DateTimeInterface|string|null $targetValidationDate = 'now';
    private static bool $checkKeyUsage = true;
    private static bool $checkBasicConstraints = true;
    private int $caSeq;
    private bool $isCA = false;

    /**
     * Recursion Limit
     */
    private static int $recur_limit = 5;

    /**
     * URL fetch flag
     */
    private static bool $disable_url_fetch = false;

    /**
     * The certificate authorities
     */
    private static array $CAs = [];

    /**
     * Binary key flag
     */
    private static bool $binary = false;

    private static array $extensions = [];

    public function __construct(PublicKey|CSR|null $cert = null)
    {
        ASN1::loadOIDs('X509');

        $startDate = new \DateTimeImmutable('now', new \DateTimeZone(@date_default_timezone_get()));
        $endDate = new \DateTimeImmutable('+1 year', new \DateTimeZone(@date_default_timezone_get()));

        /*
          "The serial number MUST be a positive integer"
          "Conforming CAs MUST NOT use serialNumber values longer than 20 octets."
           -- https://tools.ietf.org/html/rfc5280#section-4.1.2.2

          for the integer to be positive the leading bit needs to be 0 hence the
          application of a bitmap
        */
        $serialNumber = new BigInteger(Random::string(20) & ("\x7F" . str_repeat("\xFF", 19)), 256);

        $this->cert = [
            'tbsCertificate' => [
                'version' => 'v3',
                'serialNumber' => $serialNumber,
                'signature' => [
                    'algorithm' => '0.0',
                ],
                'issuer' => ['rdnSequence' => []],
                'validity' => [
                    'notBefore' => ['utcTime' => $startDate->format('Y-m-d H:i:s')],
                    'notAfter' => ['utcTime' => $endDate->format('Y-m-d H:i:s')],
                ],
                'subject' => ['rdnSequence' => []],
                'subjectPublicKeyInfo' => [
                    'algorithm' => ['algorithm' => '0.0'],
                    'subjectPublicKey' => "\0",
                ],
            ],
            'signatureAlgorithm' => [
                'algorithm' => '0.0',
            ],
            'signature' => "\0",
        ];

        if ($cert instanceof PublicKey) {
            $this->setPublicKey($cert);
        }

        if ($cert instanceof CSR) {
            $this->setPublicKey($cert->getPublicKey());
            $this->setSubjectDN($cert->getSubjectDN());
            $exts = array_unique($cert->listExtensions());
            foreach ($exts as $name) {
                $ext = $cert->getExtension($name);
                $this->setExtension($name, $ext['extnValue'], $ext['critical']);
            }
        }
    }

    // if you're going to pass an array or a Constructed object to this there's no real way to validate it so you may get random exceptions
    // $mode is only used if you're loading a string
    public static function load(string|array|Constructed $cert, int $mode = ASN1::FORMAT_AUTO_DETECT): X509
    {
        $x509 = new self();
        $x509->cert = is_string($cert) ? self::loadString($cert, $mode) : $cert;
        return $x509;
    }

    public static function addCA(string|array|Constructed $cert, int $mode = ASN1::FORMAT_AUTO_DETECT): void
    {
        $x509 = new self();
        $x509->cert = is_string($cert) ? self::loadString($cert, $mode) : $cert;
        $x509->isCA = true;
        self::$CAs[] = $x509;
    }

    public static function clearCAStore(): void
    {
        self::$CAs = [];
    }

    public static function getCAs(): array
    {
        return self::$CAs;
    }

    // this is the default behavior
    public static function strictDNComparison(): void
    {
        self::$strictDNComparison = true;
    }

    // what if you have two strings that have the same value but are of different types? eg. UTF8String vs PrintableString.
    // should those match? with strict DN comparison they wouldn't. with loose DN comparison they would.
    public static function looseDNComparison(): void
    {
        self::$strictDNComparison = false;
    }

    public static function checkKeyUsage(): void
    {
        self::$checkKeyUsage = true;
    }

    public static function ignoreKeyUsage(): void
    {
        self::$checkKeyUsage = false;
    }

    public static function checkBasicConstraints(): void
    {
        self::$checkBasicConstraints = true;
    }

    public static function ignoreBasicConstraints(): void
    {
        self::$checkBasicConstraints = false;
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

    private static function loadString(string $cert, int $mode): ?Constructed
    {
        if ($mode != ASN1::FORMAT_DER) {
            $newcert = ASN1::extractBER($cert);
            if ($mode == ASN1::FORMAT_PEM && $cert == $newcert) {
                return null;
            }
            $cert = $newcert;
        }

        $decoded = ASN1::decodeBER($cert);

        $rules = [];
        $rules['tbsCertificate']['extensions']['*'] = [self::class, 'mapInExtensions'];
        $rules['tbsCertificate']['subject']['rdnSequence']['*']['*'] = [self::class, 'mapInDNs'];
        $rules['tbsCertificate']['issuer']['rdnSequence']['*']['*'] = [self::class, 'mapInDNs'];
        $rules['tbsCertificate']['subjectPublicKeyInfo'] = function(Constructed &$cert) {
            try {
                $cert = PublicKeyLoader::load($cert->getEncoded());
            } catch (NoKeyLoadedException $e) {
            }
        };

        return ASN1::map($decoded, Maps\Certificate::MAP, $rules);
    }

    public function &offsetGet(mixed $offset): mixed
    {
        $this->compile();
        return $this->cert[$offset];
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->cert[$offset]);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->cert[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->cert[$offset]);
    }

    public function currentlyDecoded(): array|string
    {
        return $this->cert->currentlyDecoded();
    }

    public function __debugInfo(): array
    {
        $this->compile();
        return $this->cert->__debugInfo();
    }

    public function keys(): ?array
    {
        return $this->cert instanceof Constructed ? $this->cert->keys() : array_keys($this->cert);
    }

    private function mapOutDNs(string $path): void
    {
        $dns = &Arrays::subArray($this->cert, $path);
        if (!$dns) {
            return;
        }

        self::mapOutDNsInner($dns);
    }

    private function mapOutExtensions(): void
    {
        $extensions = &Arrays::subArray($this->cert, 'tbsCertificate/extensions');
        if (!$extensions || ($extensions instanceof Constructed && $extensions->hasEncoded())) {
            return;
        }

        self::mapOutExtensionsHelper($extensions);
    }

    public function toArray(): array
    {
        return $this->cert instanceof Constructed ? $this->cert->toArray() : $this->cert;
    }

    public function getPublicKey(): PublicKey
    {
        if (!$this->cert['tbsCertificate']['subjectPublicKeyInfo'] instanceof PublicKey) {
            throw new UnsupportedFormatException('Unable to decode subjectPublicKeyInfo');
        }

        $publicKey = $this->cert['tbsCertificate']['subjectPublicKeyInfo'];
        if ($publicKey instanceof RSA && $publicKey->getLoadedFormat() == 'PKCS8') {
            return $publicKey->withPadding(RSA::SIGNATURE_PKCS1);
        }
        return $publicKey;
    }

    public function setSubjectDN(array|string $props): void
    {
        self::setDNInternal($this->cert['tbsCertificate']['subject'], $props);
    }

    public function setIssuerDN(array|string $props): void
    {
        self::setDNInternal($this->cert['tbsCertificate']['issuer'], $props);
    }

    public function resetSubjectDN(): void
    {
        self::setDNInternal($this->cert['tbsCertificate']['subject'], []);
    }

    public function resetIssuerDN(): void
    {
        self::setDNInternal($this->cert['tbsCertificate']['issuer'], []);
    }

    public function removeIssuerDNProps(string $propName): void
    {
        self::removeDNPropsInternal($this->cert['tbsCertificate']['issuer'], $propName);
    }

    public function removeSubjectDNProps(string $propName): void
    {
        self::removeDNPropsInternal($this->cert['tbsCertificate']['subject'], $propName);
    }

    public function addIssuerDNProp(string $propName, string|BaseString|array|Element|Constructed $value): void
    {
        self::addDNPropsInternal($this->cert['tbsCertificate']['issuer'], $propName, $value);
    }

    public function addSubjectDNProp(string $propName, string|BaseString|array|Element|Constructed $value): void
    {
        self::addDNPropsInternal($this->cert['tbsCertificate']['subject'], $propName, $value);
    }

    public function addIssuerDNProps(string $propName, array $values): void
    {
        foreach ($values as $value) {
            $this->addIssuerDNProp($propName, $value);
        }
    }

    public function addSubjectDNProps(string $propName, array $values): void
    {
        foreach ($values as $value) {
            $this->addSubjectDNProp($propName, $value);
        }
    }

    public function hasSubjectDNProp(string $propName): bool
    {
        return self::hasDNPropsInternal($this->cert['tbsCertificate']['subject'], $propName);
    }

    public function hasIssuerDNProp(string $propName): bool
    {
        return self::hasDNPropsInternal($this->cert['tbsCertificate']['issuer'], $propName);
    }

    public function getSubjectDNProps(string $propName): array
    {
        return self::retrieveDNProps($this->cert['tbsCertificate']['subject'], $propName);
    }

    public function getIssuerDNProps(string $propName): array
    {
        return self::retrieveDNProps($this->cert['tbsCertificate']['issuer'], $propName);
    }

    public function getSubjectDN(int $format = self::DN_ARRAY): array|string
    {
        return self::formatDN($this->cert['tbsCertificate']['subject'], $format);
    }

    public function getIssuerDN(int $format = self::DN_ARRAY): array|string
    {
        return self::formatDN($this->cert['tbsCertificate']['issuer'], $format);
    }

    public function setPublicKey(PublicKey $publicKey): void
    {
        $this->cert['tbsCertificate']['subjectPublicKeyInfo'] = $publicKey;
    }

    public function hasPublicKey(): bool
    {
        return $this->cert['tbsCertificate']['subjectPublicKeyInfo'] instanceof PublicKey;
    }

    public function removePublicKey(): void
    {
        $this->cert['tbsCertificate']['subjectPublicKeyInfo'] = [
            'algorithm' => ['algorithm' => '0.0'],
            'subjectPublicKey' => "\0",
        ];
    }

    /**
     * Set certificate start date
     */
    public function setStartDate(\DateTimeInterface|string $date): void
    {
        $this->cert['tbsCertificate']['validity']['notBefore'] = ASN1::formatTime($date);
    }

    /**
     * Set certificate end date
     *
     * The CA/Browser Forum recommends that the end date not be more than 25 years out for a CA:
     * https://cabforum.org/working-groups/server/baseline-requirements/requirements/#71211-root-ca-validity
     */
    public function setEndDate(\DateTimeInterface|string $date): void
    {
        /*
          To indicate that a certificate has no well-defined expiration date,
          the notAfter SHOULD be assigned the GeneralizedTime value of
          99991231235959Z.

          -- http://tools.ietf.org/html/rfc5280#section-4.1.2.5
        */
        if (is_string($date) && strtolower($date) === 'lifetime') {
            $temp = '99991231235959Z';
            $temp = chr(ASN1::TYPE_GENERALIZED_TIME) . ASN1::encodeLength(strlen($temp)) . $temp;
            $date = ['utcTime' => new Element($temp)];
        } else {
            $date = ASN1::formatTime($date);
        }

        $this->cert['tbsCertificate']['validity']['notAfter'] = $date;
    }

    public function setSerialNumber(string|BigInteger $serial, int $base = 256): void
    {
        if (is_string($serial)) {
            $serial = new BigInteger($serial, $base);
        }
        if ($serial->isNegative()) {
            $serial = new BigInteger($serial->toBytes(true), 256);
        }
        $this->cert['tbsCertificate']['serialNumber'] = $serial;
    }

    public function count(): int
    {
        return is_array($this->cert) ? count($this->cert) : $this->cert->count();
    }

    public function rewind(): void
    {
        $this->compile();
        $this->cert->rewind();
    }

    public function current(): mixed
    {
        $this->compile();
        return $this->cert->current();
    }

    public function key(): mixed
    {
        $this->compile();
        return $this->cert->key();
    }

    public function next(): void
    {
        $this->compile();
        $this->cert->next();
    }

    public function valid(): bool
    {
        $this->compile();
        return $this->cert->valid();
    }

    private function compile(): void
    {
        if (!$this->cert instanceof Constructed) {
            $temp = self::load("$this");
            $this->cert = $temp->cert;
        }
        if ($this->cert->hasEncoded()) {
            return;
        }
        $temp = self::load("$this");
        $this->cert = $temp->cert;
    }

    public function __toString(): string
    {
        //if ($this->cert['tbsCertificate']['serialNumber']->isNegative()) {
        //    throw new \phpseclib3\Exception\UnexpectedValueException('The serial number of an X.509 certificate must be positive');
        //}

        $publicKey = $this->cert['tbsCertificate']['subjectPublicKeyInfo'];
        if ($publicKey instanceof PublicKey) {
            $origKey = $publicKey;
            $this->cert['tbsCertificate']['subjectPublicKeyInfo'] = new Element($publicKey->toString('PKCS8', ['binary' => true]));
        }

        $this->mapOutDNs('tbsCertificate/issuer/rdnSequence');
        $this->mapOutDNs('tbsCertificate/subject/rdnSequence');
        $this->mapOutExtensions();

        $cert = ASN1::encodeDER($this->cert, Maps\Certificate::MAP);

        if (isset($origKey)) {
            $this->cert['tbsCertificate']['subjectPublicKeyInfo'] = $origKey;
        }

        if (self::$binary) {
            return $cert;
        }

        return "-----BEGIN CERTIFICATE-----\r\n" . chunk_split(Strings::base64_encode($cert), 64) . '-----END CERTIFICATE-----';
    }

    public function getEncoded(): string
    {
        $this->compile();
        return $this->cert->getEncoded();
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

    public function setSubjectKeyIdentifier(string|OctetString $value): void
    {
        if (is_string($value)) {
            $value = new OctetString($value);
        }
        $this->setExtension('id-ce-subjectKeyIdentifier', $value);
    }

    /**
     * Compute a public key identifier.
     *
     * Although key identifiers may be set to any unique value, this function
     * computes key identifiers from public key according to the two
     * recommended methods (4.2.1.2 RFC 5280).
     *
     * @link https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
    */
    public function createSubjectKeyIdentifier(int $method = 1): string
    {
        if ($method != 1 && $method != 2) {
            throw new InvalidArgumentException('method must be either 1 or 2');
        }

        if (!$this->cert['tbsCertificate']['subjectPublicKeyInfo'] instanceof PublicKey) {
            throw new UnsupportedFormatException('createSubjectKeyIdentifier only works if the public key is actually recognized by phpseclib as a public key');
        }

        $key = $this->cert['tbsCertificate']['subjectPublicKeyInfo']->toString('PKCS8', ['binary' => true]);
        $hash = new Hash('sha1');
        $hash = $hash->hash($key);

        if ($method == 2) {
            $hash = substr($hash, -8);
            $hash[0] = chr((ord($hash[0]) & 0x0F) | 0x40);
        }
        $this->setExtension('id-ce-subjectKeyIdentifier', $hash);

        return $hash;
    }

    public function listExtensions(): array
    {
        if (!isset($this->cert['tbsCertificate']['extensions'])) {
            return [];
        }
        $exts = [];
        foreach ($this->cert['tbsCertificate']['extensions'] as $ext) {
            $exts[] = (string) $ext['extnId'];
        }
        return $exts;
    }

    // returns the first instance of an extension even if there are multiple instances
    // or null if said extension isn't present
    public function getExtension(string $name): ?array
    {
        $this->compile();
        if (!isset($this->cert['tbsCertificate']['extensions'])) {
            return null;
        }
        foreach ($this->cert['tbsCertificate']['extensions'] as $ext) {
            if ("$ext[extnId]" == $name) {
                return [
                    'extnId' => $name,
                    'extnValue' => $ext['extnValue'],
                    'critical' => is_bool($ext['critical']) ? $ext['critical'] : $ext['critical']->value
                ];
            }
        }
        return null;
    }

    public function hasExtension(string $name): bool
    {
        if (!isset($this->cert['tbsCertificate']['extensions'])) {
            return false;
        }
        foreach ($this->cert['tbsCertificate']['extensions'] as $ext) {
            if ("$ext[extnId]" == $name) {
                return true;
            }
        }
        return false;
    }

    // $value could be Element|BaseType|BigInteger|string|array|int|float|bool|null
    // and by array that means any of the non-array types in any combination. eg.
    // [Constructed, int] would be sufficient as would [array, BaseType]
    public function setExtension(string $name, mixed $value, ?bool $critical = null): void
    {
        $origCritical = $critical;
        if (!isset($critical)) {
            $critical = self::getExtensionCriticalValue($name);
        }
        if (isset($this->cert['tbsCertificate']['extensions'])) {
            foreach ($this->cert['tbsCertificate']['extensions'] as $i => $ext) {
                $ext = &$this->cert['tbsCertificate']['extensions'][$i];
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
            $this->cert['tbsCertificate']['extensions'] = [];
        }

        $this->cert['tbsCertificate']['extensions'][] = [
            'extnId' => $name,
            'critical' => $critical,
            'extnValue' => $value,
        ];
    }

    // remove all instances of a particular extension
    public function removeExtension(string $name): void
    {
        if (!isset($this->cert['tbsCertificate']['extensions'])) {
            return;
        }
        foreach ($this->cert['tbsCertificate']['extensions'] as $i => $ext) {
            if ("$ext[extnId]" == $name) {
                unset($this->cert['tbsCertificate']['extensions'][$i]);
            }
        }
    }

    private function testForSelfSigned(): void
    {
        $oldKeyUsage = self::$checkKeyUsage;
        $oldBasicConstraints = self::$checkBasicConstraints;
        self::$checkKeyUsage = false;
        self::$checkBasicConstraints = false;
        if (!$this->isIssuerOf($this, $this)) {
            self::$checkBasicConstraints = $oldBasicConstraints;
            self::$checkKeyUsage = $oldKeyUsage;
            throw new MethodOnlyAvailableForSelfSigned('This method is only available for self signed certificates');
        }
        self::$checkBasicConstraints = $oldBasicConstraints;
        self::$checkKeyUsage = $oldKeyUsage;
    }

    public function setDN(array|string $props): void
    {
        $this->testForSelfSigned();

        $this->setSubjectDN($props);
        $this->setIssuerDN($props);
    }

    public function resetDN(): void
    {
        $this->resetSubjectDN();
        $this->resetIssuerDN();
    }

    public function removeDNProps(string $propName): void
    {
        $this->testForSelfSigned();

        $this->removeIssuerDNProps($propName);
        $this->removeSubjectDNProps($propName);
    }

    public function addDNProp(string $propName, string|BaseString|array|Element|Constructed $value): void
    {
        $this->testForSelfSigned();

        $this->addSubjectDNProp($propName, $value);
        $this->addIssuerDNProp($propName, $value);
    }

    public function addDNProps(string $propName, array $values): void
    {
        $this->testForSelfSigned();

        $this->addSubjectDNProps($propName, $values);
        $this->addIssuerDNProps($propName, $values);
    }

    public function getDNProps(string $propName): array
    {
        $this->testForSelfSigned();

        return $this->getSubjectDNProps($propName);
    }

    public function hasDNProp(string $propName): bool
    {
        $this->testForSelfSigned();

        return $this->hasSubjectDNProp($propName);
    }

    public function getDN(int $format = self::DN_ARRAY): array|string
    {
        $this->testForSelfSigned();

        return $this->getSubjectDN($format);
    }

    public function setKeyIdentifier(string|OctetString $value): void
    {
        $this->testForSelfSigned();

        $this->setAuthorityKeyIdentifier($value);
        $this->setSubjectKeyIdentifier($value);
    }

    public function createKeyIdentifier(int $method = 1): void
    {
        $this->testForSelfSigned();

        $this->setAuthorityKeyIdentifier($this->createSubjectKeyIdentifier($method));
    }

    /**
     * Set the domain name's which the cert is to be valid for
     *
     * These days browsers usually ignore the CN DN attribute, relying exclusively on the
     * subjectAltName extension, however, some tools still look at it
     */
    public function addDomains(string ...$domains): void
    {
        if (!$this->hasSubjectDNProp('id-at-commonName')) {
            $this->addSubjectDNProp('id-at-commonName', $domains[0]);
        }
        $ext = $this->getExtension('id-ce-subjectAltName')['extnValue'] ?? [];
        foreach ($domains as $domain) {
            $ext[] = ['dNSName' => $domain];
        }
        // "If subject naming information is present only in the subjectAltName extension
        //  (e.g., a key bound only to an email address or URI), then the subject
        //  name MUST be an empty sequence and the subjectAltName extension MUST
        //  be critical."
        // -- https://www.rfc-editor.org/rfc/rfc5280#page-24
        //
        // that said, in practice, it seems like browsers do *not* support certs with
        // empty DNs, regardless of whether or not the subjectAltName extension is marked
        // as critical
        $this->setExtension('id-ce-subjectAltName', $ext, false);
    }

    /**
     * Set the IP Addresses's which the cert is to be valid for
     */
    public function addIPAddresses(string ...$ipAddresses): void
    {
        $ext = $this->getExtension('id-ce-subjectAltName')['extnValue'] ?? [];
        foreach ($ipAddresses as $ipAddress) {
            $ext[] = ['iPAddress' => $ipAddress];
        }
        $this->setExtension('id-ce-subjectAltName', $ext, false);
    }

    /**
     * Turns the certificate into a certificate authority
     */
    public function makeCA(): void
    {
        $keyUsage = $this->getExtension('id-ce-keyUsage')['extnValue'] ?? [];
        if ($keyUsage instanceof BitString) {
            $keyUsage = $keyUsage->mappedValue;
        }
        $this->setExtension(
            'id-ce-keyUsage',
            array_values(array_unique(array_merge($keyUsage, ['cRLSign', 'keyCertSign', 'digitalSignature'])))
        );
        $basicConstraints = $this->getExtension('id-ce-basicConstraints')['extnValue'] ?? [];
        if ($basicConstraints instanceof Constructed) {
            $basicConstraints = $basicConstraints->toArray();
        }
        // "Conforming CAs MUST include this extension in all CA certificates
        //  that contain public keys used to validate digital signatures on
        //  certificates and MUST mark the extension as critical in such
        //  certificates.  This extension MAY appear as a critical or non-
        //  critical extension in CA certificates that contain public keys used
        //  exclusively for purposes other than validating digital signatures on
        //  certificates.  Such CA certificates include ones that contain public
        //  keys used exclusively for validating digital signatures on CRLs and
        //  ones that contain key management public keys used with certificate
        //  enrollment protocols.  This extension MAY appear as a critical or
        //  non-critical extension in end entity certificates."
        // -- https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9
        $this->setExtension(
            'id-ce-basicConstraints',
            array_merge(['cA' => true], $basicConstraints),
            true
        );

        if (!$this->hasExtension('id-ce-subjectKeyIdentifier')) {
            $this->createSubjectKeyIdentifier();
        }
        if (!$this->hasExtension('id-ce-authorityKeyIdentifier')) {
            $this->setAuthorityKeyIdentifier($this->getExtension('id-ce-subjectKeyIdentifier')['extnValue']->value);
        }
    }

    /**
     * Register the mapping for a custom/unsupported extension.
     */
    public static function registerExtension(string $id, array $mapping): void
    {
        if (is_array(self::getMapping($id))) {
            throw new RuntimeException(
                "Extension $id has already been defined with a different mapping."
            );
        }

        self::$extensions[$id] = $mapping;
    }

    /**
     * Register the mapping for a custom/unsupported extension.
     */
    public static function getRegisteredExtension(string $id): ?array
    {
        return self::$extensions[$id] ?? null;
    }

    /**
     * Setting $date to null for this function will mean that no date validation takes place.
     * This is in contrast to what null means in the validateDate() function
     */
    public static function setTargetValidationDate(\DateTimeInterface|string|null $date = null): void
    {
        self::$targetValidationDate = $date;
    }

    public static function getTargetValidationDate(): \DateTimeInterface|string|null
    {
        return self::$targetValidationDate;
    }

    public function getSignableSection(): string
    {
        $this->compile();
        return $this->cert['tbsCertificate']->getEncoded();
    }

    public function setSignature(string $signature): void
    {
        $this->cert['signature'] = new BitString("\0$signature");
    }

    public function setSignatureAlgorithm(array $algorithm): void
    {
        $this->cert['tbsCertificate']['signature'] = $algorithm;
        $this->cert['signatureAlgorithm'] = $algorithm;
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

    /**
     * Validate an X.509 certificate against a URL
     *
     * From RFC2818 "HTTP over TLS":
     *
     * Matching is performed using the matching rules specified by
     * [RFC2459].  If more than one identity of a given type is present in
     * the certificate (e.g., more than one dNSName name, a match in any one
     * of the set is considered acceptable.) Names may contain the wildcard
     * character * which is considered to match any single domain name
     * component or component fragment. E.g., *.a.com matches foo.a.com but
     * not bar.foo.a.com. f*.com matches foo.com but not bar.com.
     */
    public function validateURL(string $url): bool
    {
        $components = parse_url($url);
        if (!isset($components['host'])) {
            throw new RuntimeException('Unable to parse URL');
        }

        if ($names = $this->getExtension('id-ce-subjectAltName')) {
            foreach ($names['extnValue'] as $name) {
                $key = $name->index;
                $value = (string) $name->value;
                $value = preg_quote($value);
                $value = str_replace('\*', '[^.]*', $value);
                switch ($key) {
                    case 'dNSName':
                        /* From RFC2818 "HTTP over TLS":

                           If a subjectAltName extension of type dNSName is present, that MUST
                           be used as the identity. Otherwise, the (most specific) Common Name
                           field in the Subject field of the certificate MUST be used. Although
                           the use of the Common Name is existing practice, it is deprecated and
                           Certification Authorities are encouraged to use the dNSName instead. */
                        if (preg_match('#^' . $value . '$#', $components['host'])) {
                            return true;
                        }
                        break;
                    case 'iPAddress':
                        /* From RFC2818 "HTTP over TLS":

                           In some cases, the URI is specified as an IP address rather than a
                           hostname. In this case, the iPAddress subjectAltName must be present
                           in the certificate and must exactly match the IP in the URI. */
                        if (preg_match('#(?:\d{1-3}\.){4}#', $components['host'] . '.') && preg_match('#^' . $value . '$#', $components['host'])) {
                            return true;
                        }
                }
            }
            return false;
        }

        if ($value = $this->getSubjectDNProps('id-at-commonName')) {
            $value = str_replace(['.', '*'], ['\.', '[^.]*'], $value[0]);
            return preg_match('#^' . $value . '$#', $components['host']) === 1;
        }

        return false;
    }

    /**
     * Validate a date
     *
     * If $date isn't defined it is assumed to be the current date.
     */
    public function validateDate(\DateTimeInterface|string|null $date = null): bool
    {
        if (!$date instanceof \DateTimeInterface) {
            $date = new \DateTimeImmutable($date ?? 'now', new \DateTimeZone(@date_default_timezone_get()));
        }

        $notBefore = $this->cert['tbsCertificate']['validity']['notBefore'];
        $notBefore = $notBefore['generalTime'] ?? $notBefore['utcTime'];

        $notAfter = $this->cert['tbsCertificate']['validity']['notAfter'];
        $notAfter = $notAfter['generalTime'] ?? $notAfter['utcTime'];

        $notBefore = new \DateTimeImmutable("$notBefore", new \DateTimeZone(@date_default_timezone_get()));
        $notAfter = new \DateTimeImmutable("$notAfter", new \DateTimeZone(@date_default_timezone_get()));

        return $date >= $notBefore && $date <= $notAfter;
    }

    /**
     * Sets the recursion limit
     *
     * When validating a signature it may be necessary to download intermediate certs from URI's.
     * An intermediate cert that linked to itself would result in an infinite loop so to prevent
     * that we set a recursion limit. A negative number means that there is no recursion limit.
     */
    public static function setRecurLimit(int $count): void
    {
        self::$recur_limit = $count;
    }

    /**
     * Prevents URIs from being automatically retrieved
     */
    public static function disableURLFetch(): void
    {
        self::$disable_url_fetch = true;
    }

    /**
     * Allows URIs to be automatically retrieved
     */
    public static function enableURLFetch(): void
    {
        self::$disable_url_fetch = false;
    }

    /**
     * Validate a signature
     *
     * Returns true if the signature is verified, false if it is not correct or on error
     *
     * By default returns false for self-signed certs. Call validateSignature(false) to make this support
     * self-signed.
     *
     * The behavior of this function is inspired by {@link http://php.net/openssl-verify openssl_verify}.
     */
    public function validateSignature(bool $caonly = true): bool
    {
        return $this->validateSignatureCountable($caonly, 0) && $this->testPathLen();
    }

    public function isIssuerOf(self|CRL $subject): bool
    {
        if (self::$checkKeyUsage && !$this->isCA) {
            if (!$this->hasExtension('id-ce-keyUsage')) {
                return false;
            }
            $expected = $subject instanceof self ? 'keyCertSign' : 'cRLSign';
            $ext = $this->getExtension('id-ce-keyUsage')['extnValue'];
            switch (true) {
                case $ext instanceof BitString && !$ext->contains($expected):
                case is_array($ext) && !in_array($expected, $ext):
                    return false;
            }
        }

        if (self::$checkBasicConstraints && !$this->isCA) {
            if (!$this->hasExtension('id-ce-basicConstraints')) {
                return false;
            }
            $ext = $this->getExtension('id-ce-basicConstraints')['extnValue'];
            switch (true) {
                case $ext['cA'] instanceof Boolean && !$ext['cA']->value:
                case is_bool($ext['cA']) && !$ext['cA']:
                    return false;
            }
        }

        switch (true) {
            case self::$strictDNComparison && $subject->getIssuerDN(self::DN_ASN1) === $this->getSubjectDN(self::DN_ASN1):
            case !self::$strictDNComparison && $subject->getIssuerDN(self::DN_CANON) === $this->getSubjectDN(self::DN_CANON):
                $authorityKey = $subject->getExtension('id-ce-authorityKeyIdentifier');
                $subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier');
                switch (true) {
                    case !isset($authorityKey) || !isset($subjectKeyID):
                    case isset($authorityKey['extnValue']['keyIdentifier']) && $authorityKey['extnValue']['keyIdentifier']->value === $subjectKeyID['extnValue']->value:
                    //case !isset($authorityKey) && !isset($subjectKeyID):
                    //case isset($subjectKeyID) && isset($authorityKey) && isset($authorityKey['extnValue']['keyIdentifier']) && $authorityKey['extnValue']['keyIdentifier']->value === $subjectKeyID['extnValue']->value:
                        if (isset($authorityKey) && isset($authorityKey['extnValue']['authorityCertSerialNumber']) && !$authorityKey['extnValue']['authorityCertSerialNumber']->equals($this['tbsCertificate']['serialNumber'])) {
                            return false;
                        }
                        return true;
                }
        }

        return false;
    }

    /**
     * Validate a signature
     *
     * Performs said validation whilst keeping track of how many times validation method is called
     */
    private function validateSignatureCountable(bool $caonly, int $count): bool
    {
        if ($count == self::$recur_limit) {
            return false;
        }

        foreach (self::$CAs as $ca) {
            // even if the cert is a self-signed one we still want to see if it's a CA;
            // if not, we'll conditionally return an error
            if ($ca->isIssuerOf($this)) {
                $signingCert = $ca;
                break;
            }
        }

        if (!isset($signingCert)) {
            if ($caonly) {
                return $this->testForIntermediate(true, $count) && $this->validateSignature(true);
            } else {
                try {
                    $this->testForSelfSigned();
                    $signingCert = $this;
                } catch (MethodOnlyAvailableForSelfSigned $e) {
                    return $this->testForIntermediate(true, $count) && $this->validateSignature(true);
                }
            }
        }

        $signatureResult = self::validateSignatureHelper(
            $signingCert->getPublicKey(),
            $this->cert['signatureAlgorithm']['algorithm'],
            $this->cert['signature'],
            $this->cert['tbsCertificate']->getEncoded()
        );
        $dateResult = isset(self::$targetValidationDate) ? $this->validateDate(self::$targetValidationDate) : true;
        $result = $signatureResult && $dateResult;
        if ($result) {
            $this->issuer = $signingCert;
            $this->issuer->caSeq = $this->issuer->caSeq ?? 0;
            $this->caSeq = $this->issuer->caSeq + 1;
        }
        return $result;
    }

    /**
     * Validates an intermediate cert as identified via authority info access extension
     *
     * See https://tools.ietf.org/html/rfc4325 for more info
     */
    private function testForIntermediate(bool $caonly, int $count): bool
    {
        $opts = $this->getExtension('id-pe-authorityInfoAccess');
        if (!isset($opts)) {
            return false;
        }
        foreach ($opts['extnValue'] as $opt) {
            if ($opt['accessMethod'] == 'id-ad-caIssuers') {
                // accessLocation is a GeneralName. GeneralName fields support stuff like email addresses, IP addresses, LDAP,
                // etc, but we're only supporting URI's. URI's and LDAP are the only thing https://tools.ietf.org/html/rfc4325
                // discusses
                if (isset($opt['accessLocation']['uniformResourceIdentifier'])) {
                    $url = (string) $opt['accessLocation']['uniformResourceIdentifier'];
                    break;
                }
            }
        }

        if (!isset($url)) {
            return false;
        }

        $cert = static::fetchURL($url);
        if (!isset($cert)) {
            return false;
        }

        /*
         "Conforming applications that support HTTP or FTP for accessing
          certificates MUST be able to accept .cer files and SHOULD be able
          to accept .p7c files." -- https://tools.ietf.org/html/rfc4325

         A .p7c file is 'a "certs-only" CMS message as specified in RFC 2797"'

         These are currently unsupported
        */
        $parent = self::load($cert);

        if (!$parent->validateSignatureCountable($caonly, ++$count)) {
            return false;
        }

        self::$CAs[] = $parent;

        return true;
    }

    /**
     * The first cert is the original CA cert and the last cert is the current cert
     * If the chain doesn't ultimately lead to a CA cert (or at least one that was imported
     * via ::addCA) then the array returned will be one long. Otherwise it'll be at least
     * two long.
     *
     * If you're trying to get the chain of a self signed cert that has a copy of itself
     * in the CA store then I guess you'll get a two element array back wherein the first
     * and last elements are the same.
     */
    public function getValidationChain(): array
    {
        if (!isset($this->issuer)) {
            $this->validateSignature();
            if (!isset($this->issuer)) {
                return [$this];
            }
        }
        $certs = [];
        $current = $this;
        while ($current->issuer) {
            array_unshift($certs, $current);
            if ($current->issuer === $current) {
                break;
            }
            $current = $current->issuer;
        }
        array_unshift($certs, $current);
        return $certs;
    }

    private function testPathLen(): bool
    {
        if (!self::$checkBasicConstraints) {
            return true;
        }
        $certs = $this->getValidationChain();
        for ($i = count($certs) - 1; $i > 0; $i--) {
            $cert = $certs[$i];
            $issuer = $cert->issuer;
            $ext = $issuer->getExtension('id-ce-basicConstraints');
            if (isset($ext['extnValue']['pathLenConstraint'])) {
                $pathLenConstraint = (int) ((string) $ext['extnValue']['pathLenConstraint']);
                if ($this->caSeq - $issuer->caSeq - 1 > $pathLenConstraint) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Fetches a URL
     */
    private static function fetchURL(string $url): ?string
    {
        if (self::$disable_url_fetch) {
            return null;
        }

        $parts = parse_url($url);
        $data = '';
        switch ($parts['scheme']) {
            case 'http':
                $fsock = @fsockopen($parts['host'], isset($parts['port']) ? $parts['port'] : 80);
                if (!$fsock) {
                    return null;
                }
                $path = $parts['path'];
                if (isset($parts['query'])) {
                    $path .= '?' . $parts['query'];
                }
                fputs($fsock, "GET $path HTTP/1.0\r\n");
                fputs($fsock, "Host: $parts[host]\r\n\r\n");
                $line = fgets($fsock, 1024);
                if (strlen($line) < 3) {
                    return null;
                }
                preg_match('#HTTP/1.\d (\d{3})#', $line, $temp);
                if ($temp[1] != '200') {
                    return null;
                }

                // skip the rest of the headers in the http response
                while (!feof($fsock) && fgets($fsock, 1024) != "\r\n") {
                }

                while (!feof($fsock)) {
                    $temp = fread($fsock, 1024);
                    if ($temp === false) {
                        return null;
                    }
                    $data .= $temp;
                }

                break;
            //case 'ftp':
            //case 'ldap':
            //default:
        }

        return $data;
    }
}