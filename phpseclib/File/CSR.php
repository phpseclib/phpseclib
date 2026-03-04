<?php

/**
 * Pure-PHP CSR Parser
 *
 * PHP version 8
 *
 * Encode and decode Certificate Signing Requests (CSRs).
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
use phpseclib4\Crypt\Common\PublicKey;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Crypt\RSA;
use phpseclib4\Exception\NoKeyLoadedException;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Element;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\ASN1\Types\BaseType;
use phpseclib4\File\ASN1\Types\BitString;
use phpseclib4\File\ASN1\Types\PrintableString;
use phpseclib4\File\ASN1\Types\UTF8String;
use phpseclib4\File\Common\Signable;

/**
 * Pure-PHP CSR Parser
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class CSR implements \ArrayAccess, \Countable, \Iterator, Signable
{
    use \phpseclib4\File\Common\Traits\Extension;
    use \phpseclib4\File\Common\Traits\DN;
    use \phpseclib4\File\Common\Traits\ASN1Signature;

    private Constructed|array $csr;

    private static array $extensions = [];

    /**
     * Binary key flag
     */
    private static bool $binary = false;

    public function __construct(PublicKey|X509|null $csr = null)
    {
        ASN1::loadOIDs('X509');

        $this->csr = [
            'certificationRequestInfo' => [
                'version' => 'v1',
                'subject' => ['rdnSequence' => []],
                'subjectPKInfo' => [
                    'algorithm' => ['algorithm' => '0.0'],
                    'subjectPublicKey' => "\0",
                ],
                'attributes' => [],
            ],
            'signatureAlgorithm' => [
                'algorithm' => '0.0',
            ],
            'signature' => "\0",
        ];

        if ($csr instanceof PublicKey) {
            $this->setPublicKey($csr);
        }

        if ($csr instanceof X509) {
            $this->setPublicKey($csr->getPublicKey());
            $this->setSubjectDN($csr->getSubjectDN());
            $exts = array_unique($csr->listExtensions());
            foreach ($exts as $name) {
                $ext = $csr->getExtension($name);
                $this->setExtension($name, $ext['extnValue'], $ext['critical']);
            }
        }
    }

    public static function load(string|array|Constructed $csr, int $mode = ASN1::FORMAT_AUTO_DETECT): CSR
    {
        $new = new self();
        $new->csr = is_string($csr) ? self::loadString($csr, $mode) : $csr;
        return $new;
    }

    private static function loadString(string $csr, int $mode): Constructed
    {
        if ($mode != ASN1::FORMAT_DER) {
            $newcsr = ASN1::extractBER($csr);
            if ($mode == ASN1::FORMAT_PEM && $csr == $newcsr) {
                throw new RuntimeException('Unable to decode PEM');
            }
            $csr = $newcsr;
        }

        $decoded = ASN1::decodeBER($csr);

        $rules = [];
        $rules['certificationRequestInfo']['attributes']['*'] = [self::class, 'mapInAttributes'];
        $rules['certificationRequestInfo']['subject']['rdnSequence']['*']['*'] = [self::class, 'mapInDNs'];
        $rules['certificationRequestInfo']['subjectPKInfo'] = function(Constructed &$csr) {
            try {
                $csr = PublicKeyLoader::load($csr->getEncoded());
            } catch (NoKeyLoadedException $e) {
            }
        };

        return ASN1::map($decoded, Maps\CertificationRequest::MAP, $rules);
    }

    public function __debugInfo(): array
    {
        $this->compile();
        return $this->csr->__debugInfo();
    }

    public function keys(): array
    {
        return $this->csr instanceof Constructed ? $this->csr->keys() : array_keys($this->csr);
    }

    private function mapOutAttributes(): void
    {
        $attributes = &Arrays::subArray($this->csr, 'certificationRequestInfo/attributes');
        if (!$attributes) {
            return;
        }

        self::mapOutAttributesHelper($attributes);
    }

    private static function mapOutAttributesHelper(array|Constructed &$attributes): void
    {
        $keys = is_array($attributes) ? array_keys($attributes) : $attributes->keys();
        foreach ($keys as $i) {
            if ($attributes[$i] instanceof Element || $attributes[$i]['value'] instanceof Element) {
                continue;
            }

            $unparsedTest = is_array($attributes[$i]) && isset($attributes[$i]['value']);
            $unparsedTest = $unparsedTest && $attributes[$i]['value'] instanceof Constructed;
            $unparsedTest = $unparsedTest && !$attributes[$i]['value']->hasMapping();
            if ($unparsedTest) {
                $wrapping = chr(ASN1::TYPE_OCTET_STRING) . ASN1::encodeLength($attributes[$i]['value']->getEncodedLength());
                $attributes[$i]['value']->setWrapping($wrapping);
                continue;
            }

            $id = (string) $attributes[$i]['type'];
            $value = &$attributes[$i]['value'];

            if ($id == 'pkcs-9-at-extensionRequest') {
                $oldValue = $value instanceof Constructed ? $value->toArray() : $value;
                foreach ($value as $i=>$subvalue) {
                    self::mapOutExtensionsHelper($value[$i]);
                }
            }

            /* [extnValue] contains the DER encoding of an ASN.1 value
               corresponding to the extension type identified by extnID */
            $map = self::getAttrMapping("$id");
            if ($map === true) {
                $map = ['type' => ASN1::TYPE_ANY];
            }

            if ($map === false) {
                //user_error($id . ' is not a currently supported extension');
                unset($attributes[$i]);
                continue;
            } else {
                foreach ($value as $i=>$subvalue) {
                    if ($value[$i] instanceof BaseType) {
                        ASN1::encodeDER($value[$i], $map);
                        $value[$i]->enableForcedCache();
                    } else {
                        $oldValue = $value[$i] instanceof Constructed ? $value[$i]->toArray() : $value[$i];
                        $temp = ASN1::encodeDER($value[$i], $map);
                        $value[$i] = ASN1::map(ASN1::decodeBER($temp), $map);
                        if ($value[$i] instanceof Constructed) {
                            $value[$i]->decoded = $oldValue;
                        }
                        $value[$i]->enableForcedCache();
                    }
                }
            }
        }

        if ($attributes instanceof Constructed) {
            if (count($attributes) - 1 != $attributes->lastKey()) {
                $attributes->rekey();
            }
        } else {
            if (count($attributes) - 1 != array_key_last($attributes)) {
                $attributes = array_values($attributes);
            }
        }
    }

    public function &offsetGet(mixed $offset): mixed
    {
        $this->compile();
        return $this->csr[$offset];
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->csr[$offset]);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->csr[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->csr[$offset]);
    }

    private static function getAttrMapping(string $id): bool|array
    {
        return match ($id) {
            'pkcs-9-at-unstructuredName' => Maps\PKCS9String::MAP,
            'pkcs-9-at-challengePassword' => Maps\DirectoryString::MAP,
            'pkcs-9-at-extensionRequest' => Maps\Extensions::MAP,

            default => false,
        };
    }

    public static function mapInAttributes(Constructed $attr): void
    {
        ASN1::disableCacheInvalidation();

        $id = "$attr[type]";
        $map = self::getAttrMapping($id);
        if ($map === false) {
            return;
        }
        $rule = [];
        if ($id == 'pkcs-9-at-extensionRequest') {
            $rule['*'] = [self::class, 'mapInExtensions'];
        }
        foreach ($attr['value'] as $key=>$value) {
            $value = &$attr['value'][$key];
            $decoded = ASN1::decodeBER($value instanceof Element ? $value->value : $value->getEncodedWithWrapping());
            $value = ASN1::map($decoded, $map, $rule);
            if ($value instanceof Constructed && $attr['value'] instanceof Constructed) {
                $value->parent = $attr['value'];
                $value->depth = $attr['value']->depth + 1;
                $value->key = $key;
            }
            unset($value);
        }

        ASN1::enableCacheInvalidation();
    }

    public function getPublicKey(): PublicKey
    {
        if (!$this->csr['certificationRequestInfo']['subjectPKInfo'] instanceof PublicKey) {
            throw new RuntimeException('Unable to decode subjectPKInfo');
        }
        $publicKey = $this->csr['certificationRequestInfo']['subjectPKInfo'];
        if ($publicKey instanceof RSA && $publicKey->getLoadedFormat() == 'PKCS8') {
            return $publicKey->withPadding(RSA::SIGNATURE_PKCS1);
        }
        return $publicKey;
    }

    public function hasPublicKey(): bool
    {
        return $this->csr['certificationRequestInfo']['subjectPKInfo'] instanceof PublicKey;
    }

    public function setPublicKey(PublicKey $publicKey): void
    {
        $this->csr['certificationRequestInfo']['subjectPKInfo'] = $publicKey;
    }

    public function removePublicKey(): void
    {
        $this->csr['certificationRequestInfo']['subjectPKInfo'] = [
            'algorithm' => ['algorithm' => '0.0'],
            'subjectPublicKey' => "\0",
        ];
    }

    public function toArray(bool $convertPrimitives = false): array
    {
        $this->compile();
        return $this->csr instanceof Constructed ? $this->csr->toArray($convertPrimitives) : $this->csr;
    }

    private function mapOutDNs(): void
    {
        $dns = &Arrays::subArray($this->csr, 'certificationRequestInfo/subject/rdnSequence');
        if (!$dns) {
            return;
        }

        self::mapOutDNsInner($dns);
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

    public function toString(array $options = []): string
    {
        $publicKey = $this->csr['certificationRequestInfo']['subjectPKInfo'] ;
        if ($publicKey instanceof PublicKey) {
            $origKey = $publicKey;
            $this->csr['certificationRequestInfo']['subjectPKInfo']  = new Element($publicKey->toString('PKCS8', ['binary' => true]));
        }

        $this->mapOutDNs();
        $this->mapOutAttributes();

        $csr = ASN1::encodeDER($this->csr, Maps\CertificationRequest::MAP);
        if (isset($origKey)) {
            $this->csr['certificationRequestInfo']['subjectPKInfo'] = $origKey;
        }

        if ($options['binary'] ?? self::$binary) {
            return $csr;
        }

        return "-----BEGIN NEW CERTIFICATE REQUEST-----\r\n" . chunk_split(Strings::base64_encode($csr), 64) . '-----END NEW CERTIFICATE REQUEST-----';
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function getSignableSection(): string
    {
        $this->compile();
        return $this->csr['certificationRequestInfo']->getEncoded();
    }

    public function setSignature(string $signature): void
    {
        $this->csr['signature'] = new BitString("\0$signature");
    }

    /**
     * Identify signature algorithm from private key
     *
     * @throws UnsupportedAlgorithmException if the algorithm is unsupported
     */
    public function identifySignatureAlgorithm(PrivateKey $key): void
    {
        $algorithm = self::identifySignatureAlgorithmHelper($key);
        $this->csr['certificationRequestInfo']['signature'] = $algorithm;
        $this->csr['signatureAlgorithm'] = $algorithm;
    }

    public function copySigningX509Attributes(X509 $x509): void
    {
        // signing a CSR with a PFX doesn't quite make as much sense as signing an X509 or CRL does
        // but, regardless, this behavior is basically analgous to this:
        // $csr = new CSR($x509);
        // $private->sign($csr);
        $this->setSubjectDN($x509->getSubjectDN());
        $exts = array_unique($x509->listExtensions());
        foreach ($exts as $name) {
            $ext = $x509->getExtension($name);
            $this->setExtension($name, $ext['extnValue'], $ext['critical']);
        }
    }

    private function compile(): void
    {
        if (!$this->csr instanceof Constructed) {
            $temp = self::load("$this");
            $this->csr = $temp->csr;
        }
        if ($this->csr->hasEncoded()) {
            return;
        }
        $temp = self::load("$this");
        $this->csr = $temp->csr;
    }

    public function setSubjectDN(array|string|Element $props): void
    {
        self::setDNInternal($this->csr['certificationRequestInfo']['subject'], $props);
    }

    public function resetSubjectDN(): void
    {
        self::setDNInternal($this->csr['certificationRequestInfo']['subject'], []);
    }

    public function removeSubjectDNProps(string $propName): void
    {
        self::removeDNPropsInternal($this->csr['certificationRequestInfo']['subject'], $propName);
    }

    public function addSubjectDNProp(string $propName, string|BaseString|array|Element|Constructed $value): void
    {
        self::addDNPropsInternal($this->csr['certificationRequestInfo']['subject'], $propName, $value);
    }

    public function addSubjectDNProps(string $propName, array $values): void
    {
        foreach ($values as $value) {
            $this->addSubjectDNProp($propName, $value);
        }
    }

    public function hasSubjectDNProp(string $propName): bool
    {
        return self::hasDNPropsInternal($this->csr['certificationRequestInfo']['subject'], $propName);
    }

    public function getSubjectDNProps(string $propName): array
    {
        return self::retrieveDNProps($this->csr['certificationRequestInfo']['subject'], $propName);
    }

    public function getSubjectDN(int $format = self::DN_STRING): array|string
    {
        return self::formatDN($this->csr['certificationRequestInfo']['subject'], $format);
    }

    public function setDN(array|string|Element $props): void
    {
        self::setSubjectDN($props);
    }

    public function resetDN(): void
    {
        self::resetSubjectDN();
    }

    public function removeDNProps(string $propName): void
    {
        self::removeSubjectDNProps($propName);
    }

    public function addDNProp(string $propName, string|BaseString|array|Element|Constructed $value): void
    {
        self::addSubjectDNProp($propName, $value);
    }

    public function addDNProps(string $propName, array $values): void
    {
        self::addSubjectDNProps($propName, $values);
    }

    public function hasDNProp(string $propName): bool
    {
        return self::hasSubjectDNProp($propName);
    }

    public function getDNProps(string $propName): array
    {
        return self::getSubjectDNProps($propName);
    }

    public function getDN(int $format = self::DN_STRING): array|string
    {
        return self::getSubjectDN($format);
    }

    public function listAttributes(): array
    {
        if (!isset($this->csr['certificationRequestInfo']['attributes'])) {
            return [];
        }
        $attrs = [];
        foreach ($this->csr['certificationRequestInfo']['attributes'] as $attr) {
            $attrs[] = (string) $attr['type'];
        }
        return $attrs;
    }

    public function listExtensions(): array
    {
        if (!isset($this->csr['certificationRequestInfo']['attributes'])) {
            return [];
        }
        $exts = [];
        foreach ($this->csr['certificationRequestInfo']['attributes'] as $attr) {
            if ($attr['type'] == 'pkcs-9-at-extensionRequest') {
                foreach ($attr['value'] as $subattr) {
                    foreach ($subattr as $ext) {
                        $exts[] = (string) $ext['extnId'];
                    }
                }
            }
        }
        return $exts;
    }

    // returns the first instance of an attribute even if there are multiple instances
    // or null if said attribute isn't present
    public function getAttribute(string $name): BaseType|Constructed|null
    {
        $this->compile();
        if (!isset($this->csr['certificationRequestInfo']['attributes'])) {
            return null;
        }
        foreach ($this->csr['certificationRequestInfo']['attributes'] as $attr) {
            if (self::extensionMatch($name, $attr['extnId'])) {
                return $attr['value'];
            }
        }
        return null;
    }

    // returns the first instance of an extension even if there are multiple instances
    // or null if said attribute isn't present
    public function getExtension(string $name): ?array
    {
        $this->compile();
        if (!isset($this->csr['certificationRequestInfo']['attributes'])) {
            return null;
        }
        foreach ($this->csr['certificationRequestInfo']['attributes'] as $attr) {
            if ($attr['type'] == 'pkcs-9-at-extensionRequest') {
                foreach ($attr['value'] as $subattr) {
                    foreach ($subattr as $ext) {
                        if (self::extensionMatch($name, $ext['extnId'])) {
                            return [
                                'extnId' => $name,
                                'extnValue' => $ext['extnValue'],
                                'critical' => is_bool($ext['critical']) ? $ext['critical'] : $ext['critical']->value
                            ];
                        }
                    }
                }
            }
        }
        return null;
    }

    public function hasAttribute(string $name): bool
    {
        if (!isset($this->csr['certificationRequestInfo']['attributes'])) {
            return false;
        }
        foreach ($this->csr['certificationRequestInfo']['attributes'] as $attr) {
            if (self::extensionMatch($name, $attr['type'])) {
                return true;
            }
        }
        return false;
    }

    public function hasExtension(string $name): bool
    {
        if (!isset($this->csr['certificationRequestInfo']['attributes'])) {
            return false;
        }
        foreach ($this->csr['certificationRequestInfo']['attributes'] as $attr) {
            if ($attr['type'] == 'pkcs-9-at-extensionRequest') {
                foreach ($attr['value'] as $subattr) {
                    foreach ($subattr as $ext) {
                        if (self::extensionMatch($name, $ext['extnId'])) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public function setAttribute(string $type, mixed $value): void
    {
        if (isset($this->csr['certificationRequestInfo']['attributes'])) {
            foreach ($this->csr['certificationRequestInfo']['attributes'] as $i => $attr) {
                $attr = &$this->csr['certificationRequestInfo']['attributes'][$i];
                if (self::extensionMatch($type, $attr['type'])) {
                    $attr['value'] = $value;
                    return;
                }
                unset($attr);
            }
        } else {
            $this->csr['certificationRequestInfo']['attributes'] = [];
        }

        $this->csr['certificationRequestInfo']['attributes'][] = [
            'type' => $type,
            'value' => $value,
        ];
    }

    public function removeAttribute(string $type): void
    {
        if (!isset($this->csr['certificationRequestInfo']['attributes'])) {
            return;
        }
        foreach ($this->csr['certificationRequestInfo']['attributes'] as $i => $attr) {
            if (self::extensionMatch($type, $attr['type'])) {
                unset($this->csr['certificationRequestInfo']['attributes'][$i]);
            }
        }
    }

    public function removeExtension(string $name): void
    {
        if (!isset($this->csr['certificationRequestInfo']['attributes'])) {
            return;
        }
        foreach ($this->csr['certificationRequestInfo']['attributes'] as $i => $attr) {
            if ("$attr[type]" == 'pkcs-9-at-extensionRequest') {
                foreach ($attr['value'] as $j => $subattr) {
                    foreach ($subattr as $k => $ext) {
                        if (self::extensionMatch($name, $ext['extnId'])) {
                            unset($this->csr['certificationRequestInfo']['attributes'][$i]['value'][$j][$k]);
                        }
                    }
                }
                unset($subattr);
            }
        }
    }

    public function setExtension(string $name, mixed $value, ?bool $critical = null): void
    {
        $origCritical = $critical;
        if (!isset($critical)) {
            $critical = self::getExtensionCriticalValue($name);
        }
        $extensionRequestTemplate = [
            'type' => 'pkcs-9-at-extensionRequest',
            'value' => [[[
                'extnId' => $name,
                'critical' => $critical,
                'extnValue' => $value,
            ]]]
        ];
        if (!isset($this->csr['certificationRequestInfo']['attributes'])) {
            $this->csr['certificationRequestInfo']['attributes'] = [$extensionRequestTemplate];
            return;
        }
        $lastExtensionRequestIdx = null;
        foreach ($this->csr['certificationRequestInfo']['attributes'] as $i => $attr) {
            if ($attr['type'] == 'pkcs-9-at-extensionRequest') {
                $lastExtensionRequestIdx = $i;
                foreach ($attr['value'] as $j => $subattr) {
                    foreach ($subattr as $k => $ext) {
                        $ext = &$this->csr['certificationRequestInfo']['attributes'][$i]['value'][$j][$k];
                        if (self::extensionMatch($name, $ext['extnId'])) {
                            $ext['extnValue'] = $value;
                            if (isset($origCritical)) {
                                $ext['critical'] = $origCritical;
                            }
                            return;
                        }
                        unset($ext);
                    }
                }
            }
        }
        if (isset($lastExtensionRequestIdx)) {
            $this->csr['certificationRequestInfo']['attributes'][$lastExtensionRequestIdx]['value'][0][] = $extensionRequestTemplate['value'][0][0];
        } else {
            $this->csr['certificationRequestInfo']['attributes'][] = $extensionRequestTemplate;
        }
    }

    /*
     * challenge passwords are mainly intended for CA's. like if you want to perform some operation
     * on the CA's website involving the X.509 cert that was created from the CSR that had the
     * challenge password you may be asked to provide said challenge password as an extra layer of
     * authentication
     */
    public function setChallengePassword(string|UTF8String|PrintableString $password): void
    {
        $value = is_string($password) || $password instanceof UTF8String ?
            ['utf8String' => $password] :
            ['printableString' => $password];
        $this->setAttribute('pkcs-9-at-challengePassword', [$value]);
    }

    public function getChallengePassword(): ?string
    {
        $attr = $this->getAttribute('pkcs-9-at-challengePassword');
        return $attr ? $attr[0]->value->value : null;
    }

    /**
     * Register the mapping for a custom/unsupported extension.
     */
    public static function registerExtension(string $id, array $mapping): void
    {
        if (!is_bool(self::getMapping($id))) {
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

    public function count(): int
    {
        return is_array($this->csr) ? count($this->csr) : $this->csr->count();
    }

    public function rewind(): void
    {
        $this->compile();
        $this->csr->rewind();
    }

    public function current(): mixed
    {
        $this->compile();
        return $this->csr->current();
    }

    public function key(): mixed
    {
        $this->compile();
        return $this->csr->key();
    }

    public function next(): void
    {
        $this->compile();
        $this->csr->next();
    }

    public function valid(): bool
    {
        $this->compile();
        return $this->csr->valid();
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
        return self::validateSignatureHelper(
            $this->getPublicKey(),
            $this->csr['signatureAlgorithm']['algorithm'],
            $this->csr['signature'],
            $this->csr['certificationRequestInfo']->getEncoded()
        );
    }
}