<?php
/**
 * Pure-PHP CMS / SignedData Parser
 *
 * PHP version 8
 *
 * Encode and decode CMS / SignedData files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\CMS;

use phpseclib4\Common\Functions\Arrays;
use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\Common\PrivateKey;
use phpseclib4\Crypt\Hash;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Element;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\ASN1\Types\BaseType;
use phpseclib4\File\ASN1\Types\BitString;
use phpseclib4\File\ASN1\Types\OctetString;
use phpseclib4\File\ASN1\Types\OID;
use phpseclib4\File\CMS;
use phpseclib4\File\CMS\SignedData\Signer;
use phpseclib4\File\Common\Signable;
use phpseclib4\File\CRL;
use phpseclib4\File\X509;

/**
 * Pure-PHP CMS / SignedData Parser
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class SignedData implements \ArrayAccess, \Countable, \Iterator, Signable
{
    use \phpseclib4\File\Common\Traits\ASN1Signature;
    use \phpseclib4\File\Common\Traits\Extension; // pretty much just for extensionMatch()

    public Constructed|array $cms;
    private ?Signer $tempSigner = null;
    /*
     * @var resource
     */
    public $fp;

    /**
     * @param string|resource $data
     */
    public function __construct(mixed $data)
    {
        if (!is_string($data) && !is_resource($data)) {
            throw new UnexpectedValueException('$data must be a string or resource');
        }
        $this->cms = [
            'contentType' => 'id-signedData',
            'content' => [
                'version' => 'v1',
                'digestAlgorithms' => [],
                'encapContentInfo' => [
                    'eContentType' => 'id-data',
                ],
                //'certificates' => [],
                //'crls' => [],
                'signerInfos' => []
            ]
        ];
        if (is_string($data)) {
            $this->cms['content']['encapContentInfo']['eContent'] = $data;
        } else {
            $this->fp = $data;
        }
    }

    // CMS::load() takes care of the PEM / DER encoding toggling
    // if you want to load an array or Constructed as a SignedData instance you'll
    // need to call CMS\SignedData::load()
    public static function load(string|array|Constructed $encoded): self
    {
        $r = new \ReflectionClass(__CLASS__);
        $cms = $r->newInstanceWithoutConstructor();
        $cms->cms = is_string($encoded) ? self::loadString($encoded) : $encoded;
        foreach ($cms['content']['signerInfos'] as $i => $signerInfo) {
            if (is_array($signerInfo)) {
                $cms['content']['signerInfos'][$i] = new Signer($signerInfo);
            }
            $signerInfo = &$cms['content']['signerInfos'][$i];
            $signerInfo->cms = $cms;
            $signerInfo->parent = $cms['content']['signerInfos'];
            $signerInfo->depth = $cms['content']['signerInfos']->depth + 1;
            $signerInfo->key = $i;
            $signerInfo->signer->parent = $cms['content']['signerInfos'];
            $signerInfo->signer->depth = $signerInfo->depth;
            $signerInfo->signer->key = $i;
            unset($signerInfo);
        }
        return $cms;
    }

    private static function loadString(string $encoded): Constructed
    {
        $decoded = ASN1::decodeBER($encoded);
        $cms = ASN1::map($decoded, Maps\ContentInfo::MAP);
        ASN1::disableCacheInvalidation();
        $rules = [];
        $rules['certificates'] = [self::class, 'mapInCerts'];
        $rules['crls'] = [self::class, 'mapInCRLs'];
        $rules['signerInfos'] = [self::class, 'mapInSigners'];
        $rules['encapContentInfo'] = [self::class, 'mapInEncapContentInfo'];
        $decoded = ASN1::decodeBER($cms['content']->value);
        $cms['content'] = ASN1::map($decoded, Maps\SignedData::MAP, $rules);
        $cms['content']->parent = $cms;
        $cms['content']->key = 'content';
        ASN1::enableCacheInvalidation();
        return $cms;
    }

    public function __debugInfo(): array
    {
        $this->compile();
        return $this->cms->__debugInfo();
    }

    private function compile(): void
    {
        if (!$this->cms instanceof Constructed) {
            $temp = self::load($this->toString(['binary' => true]));
            $this->cms = $temp->cms;
            return;
        }
        if ($this->cms->hasEncoded()) {
            return;
        }
        $temp = self::load($this->toString(['binary' => true]))['content'];
        $content = &$this->cms['content'];
        foreach ($temp as $key => $val) {
            if ($key == 'signerInfos') {
                continue;
            }
            $content[$key] = $val;
        }
    }

    public static function mapInEncapContentInfo(Constructed $eContent): void
    {
        ASN1::disableCacheInvalidation();
        if (self::extensionMatch('id-ct-TSTInfo', $eContent['eContentType'])) {
            $temp = ASN1::decodeBER((string) $eContent['eContent']);
            $eContent['eContent'] = ASN1::map($temp, Maps\TSTInfo::MAP);
        }
        ASN1::enableCacheInvalidation();
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

    public static function mapInSigners(Constructed $signers): void
    {
        ASN1::disableCacheInvalidation();
        for ($i = 0; $i < count($signers); $i++) {
            $signers[$i] = Signer::load((string) $signers[$i]->getEncoded());
        }
        ASN1::enableCacheInvalidation();
    }

    public function toString(array $options = []): string
    {
        if ($this->cms instanceof Constructed) {
            ASN1::encodeDER($this->cms['content'], Maps\SignedData::MAP);
            $cms = ASN1::encodeDER($this->cms, Maps\ContentInfo::MAP);
        } else {
            $temp = [
                'contentType' => $this->cms['contentType'], // 99% of the time this'll be 'id-signedData'
                'content' => new Element(ASN1::encodeDER($this->cms['content'], Maps\SignedData::MAP)),
            ];
            $cms = ASN1::encodeDER($temp, Maps\ContentInfo::MAP);
            $this->cms = self::load($cms)->cms;
        }

        if ($options['binary'] ?? CMS::$binary) {
            return $cms;
        }

        return "-----BEGIN CMS-----\r\n" . chunk_split(Strings::base64_encode($cms), 64) . '-----END CMS-----';
    }

    public function getSignableSection(): string
    {
        return $this->tempSigner->getSignableSection();
    }

    public function setSignature(string $signature): void
    {
        $this->tempSigner->setSignature($signature);
        unset($this->tempSigner);
    }

    /**
     * Identify signature algorithm from private key
     *
     * @throws UnsupportedAlgorithmException if the algorithm is unsupported
     */
    public function identifySignatureAlgorithm(PrivateKey $key): void
    {
        if (!isset($this->tempSigner)) {
            $x509 = new X509($key->getPublicKey());
            $x509->setExtension('id-ce-keyUsage', ['digitalSignature']);
            $private->sign($x509);
            $this->tempSigner = $this->addESSSigner($x509);
        }
        $this->tempSigner->identifySignatureAlgorithm($key);
    }

    public function copySigningX509Attributes(X509 $x509): void
    {
        $this->tempSigner = $this->addESSSigner($x509);
    }

    private function calculateVersion(): void
    {
        // based on https://www.rfc-editor.org/rfc/rfc5652#page-10
        $this->compile();
        $final = 1;
        foreach ($this->cms['content']['certificates'] as $cert) {
            $temp = match ($cert->index) {
                'other' => 5,
                'v2AttrCert' => 4,
                'v1AttrCert' => 3,
                default => 1,
            };
            if ($temp > $final) {
                $final = $temp;
            }
        }

        foreach ($this->cms['content']['crls'] as $crl) {
            $temp = match ($crl->index) {
                'other' => 5,
                'default' => 1,
            };
            if ($temp > $final) {
                $final = $temp;
            }
        }
        foreach ($this->cms['content']['signerInfos'] as $signer) {
            $temp = match ($signer['version']) {
                'v3' => 3,
                default => 1,
            };
            if ($temp > $final) {
                $final = $temp;
            }
        }
        $temp = self::extensionMatch('id-data', $this->cms['content']['encapContentInfo']['eContentType']) ? 1 : 3;
        if ($temp > $final) {
            $final = $temp;
        }
        $this->cms['content']['version'] = "v$final";
    }

    public function calculateFileHash(string $hash)
    {
        $hash = new Hash($hash);
        if (isset($this->cms['content']['encapContentInfo']['eContent'])) {
            return $hash->hash((string) $this->cms['content']['encapContentInfo']['eContent']);
        } elseif (isset($this->fp)) {
            return $hash->hash($this->fp);
        } else {
            throw new RuntimeException('There is nothing to hash');
        }
    }

    private function createSignedAttrSkeleton(X509 $x509, int $type): array
    {
        $this->cms['content']['certificates'][] = ['certificate' => $x509];

        $sid = CMS::createSIDRID($x509, $type);
        // version is the syntax version number.  If the SignerIdentifier is
        // the CHOICE issuerAndSerialNumber, then the version MUST be 1.  If
        // the SignerIdentifier is subjectKeyIdentifier, then the version
        // MUST be 3.
        $version = $type == CMS::ISSUER_AND_DN ? 'v1' : 'v3';

        $signingTime = new \DateTimeImmutable('now', new \DateTimeZone(@date_default_timezone_get()));
        $hash = $this->calculateFileHash('sha256');
        $contentType = (string) $this->cms['content']['encapContentInfo']['eContentType'];
        return [
            'version' => $version,
            'sid' => $sid,
            'digestAlgorithm' => ['algorithm' => 'id-sha256'],
            /*
            If [signedAttrs] is present, it MUST contain, at a minimum, the following two attributes:

            A content-type attribute having as its value the content type
            of the EncapsulatedContentInfo value being signed.  Section
            11.1 defines the content-type attribute.  However, the
            content-type attribute MUST NOT be used as part of a
            countersignature unsigned attribute as defined in Section 11.4.

            A message-digest attribute, having as its value the message
            digest of the content.  Section 11.2 defines the message-digest
            attribute.
            */
            'signedAttrs' => [
                ['type' => 'id-contentType', 'value' => [new OID($contentType)]],
                ['type' => 'id-messageDigest', 'value' => [new OctetString($hash)]],
                // the following aren't necessary but OpenSSL always includes them so i shall as well
                ['type' => 'id-signingTime', 'value' => ASN1::formatTime($signingTime)],
            ],
            'signatureAlgorithm' => ['algorithm' => '0.0'],
            'signature' => "\0",
        ];
    }

    public function recalculateHashAlgorithms(): void
    {
        $signers = $this->getSigners();
        $algos = [];
        foreach ($signers as $signer) {
            foreach ($algos as $algo) {
                if ($signer['digestAlgorithm']['algorithm'] === $algo['algorithm']) {
                    continue;
                }
            }
            $algos[] = $signer['digestAlgorithm'];
        }
        $this->cms['content']['digestAlgorithms'] = $algos;
    }

    private function createSigner(array $skeleton): Signer
    {
        $signer = new Signer($skeleton);
        // make Signer point to SignedData
        $signer->cms = $this;
        $signer->compile();
        $this->compile();
        $this->cms['content']['signerInfos'][] = $signer;
        // make Signer Constructed point to SignedData Constructed
        $signer->signer->parent = $this->cms['content']['signerInfos'];
        $signer->signer->key = count($this->cms['content']['signerInfos']) - 1;
        // [digestAlgorithms] is intended to list the message digest algorithms employed by all of the signers, in any
        // order, to facilitate one-pass signature verification. Implementations MAY fail to validate signatures that
        // use a digest algorithm that is not included in this set.
        $algorithms = $this->cms['content']['digestAlgorithms'];
        if ($algorithms instanceof Constructed) {
            $algorithms = $algorithms->toArray();
        }
        $list = array_column($algorithms, 'algorithm');
        if (!in_array('id-sha256', $list)) {
            $this->cms['content']['digestAlgorithms'][] = ['algorithm' => 'id-sha256'];
        }
        $this->calculateVersion();
        return $signer;
    }

    public function addESSSigner(X509 $x509, int $type = CMS::ISSUER_AND_DN): Signer
    {
        $skeleton = $this->createSignedAttrSkeleton($x509, $type);
        $hash = new Hash('sha256');
        $hash = $hash->hash($x509->getEncoded());
        $skeleton['signedAttrs'][] = [
            'type' => 'id-aa-signingCertificateV2',
            'value' => [[
                'certs' => [[
                    // hashAlgorithm is new to id-aa-signingCertificateV2 - in id-aa-signingCertificate it was *always* sha1
                    'hashAlgorithm' => ['algorithm' => 'id-sha256'],
                    'certHash' => new OctetString($hash),
                    'issuerSerial' => [
                        'issuer' => [['directoryName' => $x509['tbsCertificate']['issuer']]],
                        'serialNumber' => $x509['tbsCertificate']['serialNumber'],
                    ]
                ]]
            ]]
        ];
        return $this->createSigner($skeleton, $x509);
    }

    public function addNakedSigner(X509 $x509, int $type = CMS::ISSUER_AND_DN): Signer
    {
        // When [signedAttrs] is absent, the result is just the message digest of the [the encapContentInfo eContent OCTET STRING].
        // ...
        // [signedAttrs] is optional, but it MUST be present if the content type of the EncapsulatedContentInfo value being signed
        // is not id-data.
        $skeleton = $this->createSignedAttrSkeleton($x509, $type);
        unset($skeleton['signedAttrs']);
        return $this->createSigner($skeleton);
    }

    public function addSigner(X509 $x509, int $type = CMS::ISSUER_AND_DN): Signer
    {
        $skeleton = $this->createSignedAttrSkeleton($x509, $type);
        return $this->createSigner($skeleton);
    }

    public function addSignature(Signer $signer)
    {
        $this->compile();
        $this->addCertificate(($signer->getCertificate()));
        $this->cms['content']['signerInfos'][] = $signer;
        $signer->parent = $this->cms['content']['signerInfos'];
        $signer->key = count($this->cms['content']['signerInfos']) - 1;
        $signer->depth = $this->cms['content']['signerInfos']->depth + 1;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    private function mapOutDNs(string $path): void
    {
        $dns = &Arrays::subArray($this->cms, $path);
        if (!$dns) {
            return;
        }

        self::mapOutDNsInner($dns);
    }

    public function &offsetGet(mixed $offset): mixed
    {
        $this->compile();
        return $this->cms[$offset];
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->cms[$offset]);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->cms[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->cms[$offset]);
    }

    public function count(): int
    {
        return is_array($this->cms) ? count($this->cms) : $this->cms->count();
    }

    public function rewind(): void
    {
        $this->compile();
        $this->cms->rewind();
    }

    public function current(): mixed
    {
        $this->compile();
        return $this->cms->current();
    }

    public function key(): mixed
    {
        $this->compile();
        return $this->cms->key();
    }

    public function next(): void
    {
        $this->compile();
        $this->cms->next();
    }

    public function valid(): bool
    {
        $this->compile();
        return $this->cms->valid();
    }

    public function keys(): array
    {
        return $this->cms instanceof Constructed ? $this->cms->keys() : array_keys($this->cms);
    }

    public function toArray(bool $convertPrimitives = false): array
    {
        $this->compile();
        return $this->cms instanceof Constructed ? $this->cms->toArray($convertPrimitives) : $this->cms;
    }

    public function getSigners(): array
    {
        $this->compile();
        $signers = [];
        foreach ($this->cms['content']['signerInfos'] as $signer) {
            $signers[] = $signer;
        }
        return $signers;
    }

    public function findSigner(X509 $x509): ?Signer
    {
        $this->compile();
        foreach ($this->cms['content']['signerInfos'] as $signer) {
            if ($signer->matchesX509($x509)) {
                return $signer;
            }
        }
        return null;
    }

    /**
     * @param string|resource $data
     */
    public function attach(mixed $data): void
    {
        if (!is_string($data) && !is_resource($data)) {
            throw new UnexpectedValueException('$data should be either a resource or a string');
        }
        if (is_resource($data)) {
            $this->fp = $data;
        } else {
            $this->cms['content']['encapContentInfo']['eContent'] = $data;
        }
    }

    public function detach()
    {
        $this->fp = null;
        unset($this->cms['content']['encapContentInfo']['eContent']);
    }

    public function getCertificates(): array
    {
        $certs = [];
        foreach ($this->cms['content']['certificates'] as $cert) {
            switch (true) {
                // standard X509 cert
                case isset($cert['certificate']): // && $cert['certificate'] instanceof X509:
                    $certs[] = $cert['certificate'];
                //    break;
                // extended certificates are basically wrappers around regular X509 certs with unsigned attributes
                // living alongside the cert. this was intended for pre-v3 X509 certs where extensions were not
                // included
                //case isset($cert['extendedCertificate']): // obsolete
                    //if ($this->isSignedBy($cert['extendedCertificate']['certificate'])) {
                    //    $signingCert = $cert['extendedCertificiate']['certificate'];
                    //}
                    //break;
                //case isset($cert['v1AttrCert']): // obsolete
                    // ['v1AttrCert']['acInfo'] = $AttributeCertificateInfoV1 ?
                //case isset($cert['v2AttrCert']):
                    // ['v2AttrCert']['acInfo'] = $AttributeCertificateInfo ?
                //case isset($cert['other']):
                    // ['other']['otherCert'] = ???
                //    continue 2;
            }
        }
        return $certs;
    }

    public function addCertificate(X509 $cert): void
    {
        $this->cms['content']['certificates'][] = ['certificate' => $cert];
    }

    public function addCRL(CRL $crl): void
    {
        $this->cms['content']['crls'][] = $crl;
    }

    /**
     * Validate a signature
     */
    public function validateSignature(bool $caonly = true): bool
    {
        $this->compile();

        $matches = 0;

        foreach ($this->cms['content']['signerInfos'] as $signer) {
            if ($signer->validateSignature($caonly)) {
                $matches++;
            }
        }

        return count($this->cms['content']['signerInfos']) == $matches;
    }

    public function getEncoded(): string
    {
        $this->compile();
        return $this->cms->getEncoded();
    }

    public function hasEncoded(): bool
    {
        //$this->compile();
        return $this->cms->hasEncoded();
    }
}