<?php
/**
 * Pure-PHP CMS / SignedData Parser
 *
 * PHP version 8
 *
 * Encode and decode CMS / SignedData / SignerInfo files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File\CMS\SignedData;

use phpseclib4\Common\Functions\Arrays;
use phpseclib4\Crypt\Common\PrivateKey;
use phpseclib4\Crypt\Hash;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\ASN1\Types\BitString;
use phpseclib4\File\ASN1\Types\OctetString;
use phpseclib4\File\CMS\SignedData;
use phpseclib4\File\Common\Signable;
use phpseclib4\File\X509;

class Signer implements \ArrayAccess, \Countable, \Iterator, Signable
{
    use \phpseclib4\File\Common\Traits\ASN1Signature;
    use \phpseclib4\File\Common\Traits\DN;
    use \phpseclib4\File\Common\Traits\Extension; // pretty much just for extensionMatch()

    public Constructed|array|null $signer;
    public ?SignedData $cms = null;
    public Choice|Constructed|null $parent;
    public int $depth = 0;
    public int|string $key;

    public function __construct(Constructed|array|null $signer = null)
    {
        $this->signer = $signer;
    }

    public static function load(string|array|Constructed $encoded): self
    {
        $signer = new self();
        $signer->signer = is_string($encoded) ? self::loadString($encoded) : $encoded;
        return $signer;
    }

    private static function loadString(string $encoded): Constructed
    {
        //ASN1::disableCacheInvalidation();
        $rules = [];
        $rules['signedAttrs']['*'] = [self::class, 'mapInAttrs'];
        $rules['unsignedAttrs']['*'] = [self::class, 'mapInAttrs'];
        $rules['sid']['issuerAndSerialNumber']['issuer']['rdnSequence']['*']['*'] = [self::class, 'mapInDNs'];
        $decoded = ASN1::decodeBER($encoded);
        $signer = ASN1::map($decoded, Maps\SignerInfo::MAP, $rules);
        //ASN1::enableCacheInvalidation();
        return $signer;
    }

    private function mapOutDNs(string $path): void
    {
        $dns = &Arrays::subArray($this->signer, $path);
        if (!$dns) {
            return;
        }
        self::mapOutDNsInner($dns);
    }

    public function toString(): string
    {
        $this->mapOutAttrs('signedAttrs', $this->signer);
        $this->mapOutAttrs('unsignedAttrs', $this->signer);
        $this->mapOutDNs('sid/issuerAndSerialNumber/issuer/rdnSequence');

        $signer = ASN1::encodeDER($this->signer, Maps\SignerInfo::MAP);

        return $signer;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    private static function getAttrMapping(string $attrType): array|null
    {
        return match ($attrType) {
            'id-aa-signingCertificate' => Maps\SigningCertificate::MAP,
            'id-aa-signingCertificateV2' => Maps\SigningCertificateV2::MAP,
            'id-aa-CMSAlgorithmProtection' => Maps\CMSAlgorithmProtection::MAP,
            'id-aa-timeStampToken' => Maps\TimeStampToken::MAP,
            'pkcs-9-at-smimeCapabilities' => Maps\SMIMECapabilities::MAP,
            default => null
        };
    }

    private static function mapOutAttrs(string $idx, array|Constructed &$info): void
    {
        if (!isset($info[$idx]) || $info[$idx] instanceof Element) {
            return;
        }
        $attrs = &$info[$idx];
        $keys = is_array($attrs) ? array_keys($attrs) : $attrs->keys();
        foreach ($keys as $i) {
            switch (true) {
                case $attrs[$i] instanceof Element:
                case $attrs[$i]['value'] instanceof Element:
                case $attrs[$i] instanceof Constructed && $attrs[$i]->hasEncoded():
                    continue 2;
            }

            $id = (string) $attrs[$i]['type'];
            $values = &$attrs[$i]['value'];
            $map = self::getAttrMapping($id);
            if (is_null($map)) {
                continue;
            }
            foreach ($values as $j => $value) {
                if ($id == 'id-aa-signingCertificate' || $id == 'id-aa-signingCertificateV2') {
                    $dns = &Arrays::subArrayWithWildcards($values[$j], 'certs/*/issuerSerial/issuer/*/directoryName/rdnSequence');
                    if ($dns) {
                        self::mapOutDNsInner($dns);
                        $value = $values[$j];
                    }
                }
                if ($value instanceof BaseType) {
                    if ($value instanceof Constructed) {
                        $value->invalidateCache();
                    }
                    ASN1::encodeDER($value, $map);
                } else {
                    $temp = ASN1::encodeDER($value, $map);
                    $values[$j] = ASN1::map(ASN1::decodeBER($temp), $map);
                    $values[$j]->enableForcedCache();
                }
            }
        }

        if ($attrs instanceof Constructed) {
            if (count($attrs) - 1 != $attrs->lastKey()) {
                $attrs->rekey();
            }
        } else {
            if (count($attrs) - 1 != array_key_last($attrs)) {
                $attrs = array_values($attrs);
            }
        }
    }

    public static function mapInAttrs(Constructed $attr): void
    {
        if (self::extensionMatch('id-aa-timeStampToken', $attr['type'])) {
            ASN1::disableCacheInvalidation();
            for ($i = 0; $i < count($attr['value']); $i++) {
                $attr['value'][$i] = SignedData::load((string) $attr['value'][$i]);
            }
            ASN1::enableCacheInvalidation();
            return;
        }
        $map = self::getAttrMapping("$attr[type]");
        if (is_null($map)) {
            return;
        }
        $rules = [];
        switch ($attr['type']) {
            case 'id-aa-signingCertificate':
            case 'id-aa-signingCertificateV2':
                $rules['certs']['*']['issuerSerial']['issuer']['*']['directoryName']['rdnSequence']['*']['*'] = [self::class, 'mapInDNs'];
        }
        ASN1::disableCacheInvalidation();
        for ($i = 0; $i < count($attr['value']); $i++) {
            $attr['value'][$i] = ASN1::map(ASN1::decodeBER($attr['value'][$i]->value), $map, $rules);
            $attr['value'][$i]->parent = $attr['value'];
            $attr['value'][$i]->key = $i;
            $attr['value'][$i]->depth = $attr['value']->depth + 1;
        }
        ASN1::enableCacheInvalidation();
    }

    public function listSignedAttrs(): array
    {
        $names = [];
        foreach ($this->signer['signedAttrs'] as $attr) {
            $names[] = (string) $attr['type'];
        }
        return $names;
    }

    public function hasSignedAttr(string $type): bool
    {
        return $this->getSignedAttr($type) !== null;
    }

    public function getSignedAttr(string $type): ?Constructed
    {
        $this->compile();
        foreach ($this->signer['signedAttrs'] as $attr) {
            if (self::extensionMatch($type, $attr['type'])) {
                return $attr['value'];
            }
        }
        return null;
    }

    public function setSignedAttr(string $type, mixed $value): void
    {
        $this->compile();
        for ($i = 0; $i < count($this->signer['signedAttrs']); $i++) {
            $attr = &$this->signer['signedAttrs'][$i];
            if (self::extensionMatch($type, $attr['type'])) {
                $attr['value'] = [$value];
                return;
            }
        }
        $this->signer['signedAttrs'][] = ['type' => $type, 'value' => [$value]];
    }

    public function listUnsignedAttrs(): array
    {
        $names = [];
        foreach ($this->signer['unsignedAttrs'] as $attr) {
            $names[] = (string) $attr['type'];
        }
        return $names;
    }

    public function hasUnsignedAttr(string $type): bool
    {
        return $this->getUnsignedAttr($type) !== null;
    }

    public function getUnsignedAttr(string $type): ?Constructed
    {
        $this->compile();
        foreach ($this->signer['unsignedAttrs'] as $attr) {
            if (self::extensionMatch($type, $attr['type'])) {
                return $attr['value'];
            }
        }
        return null;
    }

    public function setUnsignedAttr(string $type, mixed $value): void
    {
        $this->compile();
        for ($i = 0; $i < count($this->signer['unsignedAttrs']); $i++) {
            $attr = &$this->signer['unsignedAttrs'][$i];
            if (self::extensionMatch($type, $attr['type'])) {
                $attr['value'] = [$value];
                return;
            }
        }
        $this->signer['unsignedAttrs'][] = ['type' => $type, 'value' => [$value]];
    }

    public function matchesX509(X509 $x509): bool
    {
        /*
          The recipient MAY obtain the correct public key for the signer
          by any means, but the preferred method is from a certificate obtained
          from the SignedData certificates field.
        */
        $ESSCertID = $this->getSignedAttr('id-aa-signingCertificate');
        $ESSCertIDv2 = $this->getSignedAttr('id-aa-signingCertificateV2');
        if (isset($ESSCertIDv2) || isset($ESSCertID)) {
            if (isset($ESSCertIDv2)) {
                $expected = $ESSCertIDv2[0]['certs'][0];
                $hash = preg_replace('#^id-#', '', (string) $expected['hashAlgorithm']['algorithm']);
            } else {
                $expected = $ESSCertID[0]['certs'][0];
                $hash = 'sha1';
            }
            $expectedHash = (string) $expected['certHash'];
            $expectedCert = [
                'issuerAndSerialNumber' => [
                    'issuer' => $expected['issuerSerial']['issuer'][0]['directoryName'],
                    'serialNumber' => $expected['issuerSerial']['serialNumber'],
                ]
            ];
            $hash = new Hash($hash);
        }
        if (isset($expected)) {
            $certHash = $hash->hash($x509->getEncoded());
            if (!hash_equals($expectedHash, $certHash)) {
                return false;
            }
            // uncomment the following out to look at EITHER the ESS attribute or $this->>signer['sid']
            //if (!isset($expectedCert) || $cert->isIssuerOf($expectedCert)) {
            //    return $cert;
            //}
            //continue;
            // "The digitalSignature bit is asserted when the subject public key
            //  is used for verifying digital signatures, other than signatures on
            //  certificates (bit 5) and CRLs (bit 6)"
            // -- https://datatracker.ietf.org/doc/html/rfc5280#page-30
            //
            // in spite of the above, a lot of EU certs use nonRepudiation, exclusively,
            // so we'll support that as well
            if (isset($expectedCert) && !$x509->isIssuerOf($expectedCert, ['digitalSignature', 'nonRepudiation'])) {
                return false;
            }
        }

        return $x509->isIssuerOf($this->signer['sid'], ['digitalSignature', 'nonRepudiation']);
    }

    public function getCertificate(): ?X509
    {
        foreach ($this->cms['content']['certificates'] as $cert) {
            switch (true) {
                // standard X509 cert
                case isset($cert['certificate']): // && $cert['certificate'] instanceof X509:
                    $cert = $cert['certificate'];
                    break;
                // extended certificates are basically wrappers around regular X509 certs with unsigned attributes
                // living alongside the cert. this was intended for pre-v3 X509 certs where extensions were not
                // included
                case isset($cert['extendedCertificate']): // obsolete
                    //$cert = $cert['extendedCertificiate']['certificate'];
                    //break;
                case isset($cert['v1AttrCert']): // obsolete
                    // ['v1AttrCert']['acInfo'] = $AttributeCertificateInfoV1 ?
                case isset($cert['v2AttrCert']):
                    // ['v2AttrCert']['acInfo'] = $AttributeCertificateInfo ?
                case isset($cert['other']):
                    // ['other']['otherCert'] = ???
                    continue 2;
            }
            if ($this->matchesX509($cert)) {
                return $cert;
            }
        }
        return null;
    }

    private function setHash(string $hash): void
    {
        $origHash = strtolower($hash);
        $hash = match ($hash) {
            'md2' => 'md2',
            'md4' => 'md4',
            'md5' => 'md5',
            'sha1' => 'id-sha1',
            'sha256' => 'id-sha256',
            'sha384' => 'id-sha384',
            'sha224' => 'id-sha224',
            'sha512/224' => 'id-sha512/224',
            'sha512/256' => 'id-sha512/256',
            'sha512' => 'id-sha512',
            default => null
        };
        if (!isset($hash)) {
            throw new UnsupportedAlgorithmException("$origHash is not a supported algorithm: try md2, md4, md5, sha1, sha224, sha256, sha384, sha512, sha512/224 or sha512/256 instead");
        }
        $hashObj = new Hash($origHash);
        $this->compile();
        $this->signer['digestAlgorithm'] = ['algorithm' => $hash];
        if (count($this->signer['signedAttrs'])) {
            $messageDigest = $this->cms->calculateFileHash($origHash);
            // explicitly setting the following to OctetString is necessary because AttributeValue is type ANY and
            // if ANY is encountered with a string ASN1::encodeDER will assume the type is UTF8_STRING - not OCTET_STRING.
            $this->setSignedAttr('id-messageDigest', new OctetString($messageDigest));
            for ($i = 0; $i < count($this->signer['signedAttrs']); $i++) {
                $attr = &$this->signer['signedAttrs'][$i];
                if (self::extensionMatch('id-aa-signingCertificateV2', $attr['type'])) {
                    $checkKeyUsage = X509::isCheckKeyUsageEnabled();
                    if ($checkKeyUsage) {
                        X509::ignoreKeyUsage();
                    }
                    $cert = $this->getCertificate();
                    if ($checkKeyUsage) {
                        X509::checkKeyUsage();
                    }
                    if (!isset($cert)) {
                        throw new RuntimeException('Unable to find matching id-aa-signingCertificateV2 certificate');
                    }
                    $attr['value'][0]['certs'][0]['hashAlgorithm'] = ['algorithm' => $hash];
                    // explicitly setting the following to OctetString isn't needed as Hash is type OCTET_STRING, however,
                    // since we're explicitly setting it for id-messageDigest, above, we might as well be consistent
                    $attr['value'][0]['certs'][0]['certHash'] = new OctetString($hashObj->hash($cert->getEncoded()));
                }
            }
        }
        $this->cms->recalculateHashAlgorithms();
    }

    public function validateSignature(bool $caonly = true): bool
    {
        if (count($this->signer['signedAttrs']))
        {
            $messageDigest = $this->cms->calculateFileHash(preg_replace('#^id-#', '', (string) $this->signer['digestAlgorithm']['algorithm']));
            $expectedDigest = $this->getSignedAttr('id-messageDigest');
            if (!isset($expectedDigest)) {
                return false;
            }
            if (!hash_equals($messageDigest, (string) $expectedDigest[0])) {
                return false;
            }
        }

        $signingCert = $this->getCertificate();
        if (!isset($signingCert)) {
            return false;
        }

        $algo = (string) $this->signer['signatureAlgorithm']['algorithm'];
        if ($algo == 'rsaEncryption') {
            $algo = match ((string) $this->signer['digestAlgorithm']['algorithm']) {
                'id-md2' => 'md2WithRSAEncryption',
                'id-md5' => 'md5WithRSAEncryption',
                'id-sha1' => 'sha1WithRSAEncryption',
                'id-sha224' => 'sha224WithRSAEncryption',
                'id-sha256' => 'sha256WithRSAEncryption',
                'id-sha384' => 'sha384WithRSAEncryption',
                'id-sha512' => 'sha512WithRSAEncryption',
                'id-sha512/224' => 'sha512-224WithRSAEncryption',
                'id-sha512/256' => 'sha512-256WithRSAEncryption',
                default => null
            };
            if (!isset($algo)) {
                throw new UnsupportedAlgorithmException($this->signer['digestAlgorithm']['algorithm'] . ' is not a supported digest algorithm');
            }
        }
        /*
        The IMPLICIT [0] tag in the signedAttrs is not used for the DER
        encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
        encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0]
        tag, MUST be included in the message digest calculation along with
        the length and content octets of the SignedAttributes value.
        */
        $signatureSubject = count($this->signer['signedAttrs']) ?
            chr(ASN1::TYPE_SET | 0x20) . substr((string) $this->signer['signedAttrs'], 1) :
            (string) $this->cms['content']['encapContentInfo']['eContent'];

        if ($caonly && !$signingCert->validateSignature()) {
            return false;
        }

        // for X509's, CRL's and CSR's signatures are BIT STRINGs. for CMS's they're OCTET STRINGs.
        return self::validateSignatureHelper(
            $signingCert->getPublicKey(),
            $algo,
            new BitString("\0" . $this->signer['signature']),
            $signatureSubject
        );
    }

    public function getSignableSection(): string
    {
        if (isset($this->signer['signedAttrs'])) {
            $this->compile();
            return chr(ASN1::TYPE_SET | 0x20) . substr((string) $this->signer['signedAttrs'], 1);
        } else {
            return (string) $this->cms['content']['encapContentInfo']['eContent'];
        }
    }

    public function setSignature(string $signature): void
    {
        $this->signer['signature'] = new OctetString("$signature");
    }

    /**
     * Identify signature algorithm from private key
     *
     * @throws UnsupportedAlgorithmException if the algorithm is unsupported
     */
    public function identifySignatureAlgorithm(PrivateKey $key): void
    {
        $algorithm = self::identifySignatureAlgorithmHelper($key);
        $this->signer['signatureAlgorithm'] = $algorithm;
        $this->setHash((string) $key->getHash());
    }

    public function copySigningX509Attributes(X509 $x509): void
    {
        $expected = $this->getCertificate();
        $addCert = true;
        if (isset($expected)) {
            $expected = (string) $expected;
            $total = 0;
            // we only want to replace the cert if there's only one signer using that cert
            foreach ($this->cms->getSigners() as $signer) {
                $found = (string) $signer->getCertificate();
                if ($found === $expected) {
                    $total++;
                }
            }
            if ($total === 1) {
                $addCert = false;
                for ($i = 0; $i < count($this->cms['content']['certificates']); $i++) {
                    switch (true) {
                        case isset($this->cms['content']['certificates'][$i]['certificate']):
                            $found = (string) $this->cms['content']['certificates'][$i]['certificate'];
                        //    break;
                        //case isset($this->cms['content']['certificates'][$i]['extendedCertificate']['certificate']):
                        //    $found = (string) $this->cms['content']['certificates'][$i]['extendedCertificate']['certificate'];
                    }
                    if ($found === $expected) {
                        $this->cms['content']['certificates'][$i]['certificate'] = $x509;
                    }
                }
            }
        }
        if ($addCert) {
            $this->cms->addCertificate($x509);
        }
        $sid = ['issuerAndSerialNumber' =>
            [
                'issuer' => $x509['tbsCertificate']['issuer'],
                'serialNumber' => $x509['tbsCertificate']['serialNumber'],
            ]
        ];
        $this->signer['sid'] = $sid;
        $this->signer['version'] = 'v1';
        for ($i = 0; $i < count($this->signer['signedAttrs']); $i++) {
            $attr = &$this->signer['signedAttrs'][$i];
            if (self::extensionMatch('id-aa-signingCertificateV2', $attr['type'])) {
                $hash = preg_replace('#^id-#', '', (string) $attr['value'][0]['certs'][0]['hashAlgorithm']['algorithm']);
                $hash = new Hash($hash);
                $attr['value'][0]['certs'][0]['certHash'] = new OctetString($hash->hash($x509->getEncoded()));
                // the following errors out and idk why
                //$attr['value'][0]['certs'][0]['issuerSerial']['issuer'][0]['directoryName'] = $x509['tbsCertificate']['issuer'];
                // consequently we do this:
                $attr['value'][0]['certs'][0]['issuerSerial']['issuer'][0] = ['directoryName' => $x509['tbsCertificate']['issuer']];
                $attr['value'][0]['certs'][0]['issuerSerial']['serialNumber'] = $x509['tbsCertificate']['serialNumber'];
                break;
            }
        }
    }

    public function __debugInfo(): array
    {
        $this->compile();
        return $this->signer->__debugInfo();
    }

    public function compile(): void
    {
        if (!$this->signer instanceof Constructed) {
            $temp = self::load("$this");
            $this->signer = $temp->signer;
            return;
        }
        if ($this->signer->hasEncoded()) {
            return;
        }
        $oldParent = $this->signer->parent;
        $temp = self::load("$this");
        $this->signer = $temp->signer;
        $this->signer->parent = $oldParent;
    }

    public function &offsetGet(mixed $offset): mixed
    {
        $this->compile();
        return $this->signer[$offset];
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->signer[$offset]);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->signer[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->signer[$offset]);
    }

    public function count(): int
    {
        return is_array($this->signer) ? count($this->signer) : $this->signer->count();
    }

    public function rewind(): void
    {
        $this->compile();
        $this->signer->rewind();
    }

    public function current(): mixed
    {
        $this->compile();
        return $this->signer->current();
    }

    public function key(): mixed
    {
        $this->compile();
        return $this->signer->key();
    }

    public function next(): void
    {
        $this->compile();
        $this->signer->next();
    }

    public function valid(): bool
    {
        $this->compile();
        return $this->signer->valid();
    }

    public function keys(): array
    {
        return $this->signer instanceof Constructed ? $this->signer->keys() : array_keys($this->signer);
    }

    public function toArray(bool $convertPrimitives = false): array
    {
        $this->compile();
        return $this->signer instanceof Constructed ? $this->signer->toArray($convertPrimitives) : $this->signer;
    }

    public function getEncoded(): string
    {
        $this->compile();
        return $this->signer->getEncoded();
    }

    public function hasEncoded(): bool
    {
        $this->compile();
        return $this->signer->hasEncoded();
    }
}