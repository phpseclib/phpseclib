<?php

/**
 * Pure-PHP PFX (PKCS#12) Parser
 *
 * The PFX RFC is quite terrible, as discussed in https://www.cs.auckland.ac.nz/~pgut001/pubs/pfx.html
 *
 * PHP version 8
 *
 * Encode and decode PFX files.
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2022 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\File;

use phpseclib4\Crypt\Common\PrivateKey;
use phpseclib4\Crypt\Hash;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Crypt\Random;
use phpseclib4\Exception\NoPasswordProvidedException;
use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\Exception\UnsupportedOperationException;
use phpseclib4\File\Common\Signable;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Element;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\ASN1\Types\BaseString;
use phpseclib4\File\ASN1\Types\OctetString;

/**
 * Pure-PHP PFX (PKCS#12) Parser
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class PFX implements \ArrayAccess, \Countable, \Iterator
{
    use \phpseclib4\Crypt\Common\Traits\ASN1AlgorithmIdentifier;

    public Constructed|array $pfx;
    private ?string $password = null;

    // same as OpenSSL
    // setting this to null will mean that a MAC isn't included
    private static ?string $defaultHashAlgorithm = 'sha256';
    // same as OpenSSL
    // https://www.rfc-editor.org/rfc/rfc7292#page-23 says this:
    // "The iteration count is recommended to be 1024 or more."
    //private static int $defaultIterationCount = 2048;
    // differs from OpenSSL, which defaults to 8, regardless of the hash
    // https://www.rfc-editor.org/rfc/rfc7292#page-23, however, states this:
    // "Ideally, the salt is as long as the output of the hash function being
    //  used and consists of completely random bits."
    private static int $defaultSaltLength = 32;

    public function __construct()
    {
        ASN1::loadOIDs('CMS');
        ASN1::loadOIDs('PFX');

        $this->pfx = [
            'version' => 'v3',
            'authSafe' => [
                'contentType' => 'id-data',
                'content' => []
            ]
        ];
    }

    public static function load(string|array|Constructed $pfx, ?string $password = null): self
    {
        $temp = new self();
        $temp->pfx = is_string($pfx) ? self::loadString($pfx, $password) : $pfx;
        $temp->password = $password;
        return $temp;
    }

    private static function loadString(string $pfx, ?string $password): Constructed
    {
        ASN1::disableCacheInvalidation();

        $decoded = ASN1::decodeBER($pfx);
        $pfx = ASN1::map($decoded, ASN1\Maps\PFX::MAP);

        $decoded = ASN1::decodeBER($pfx['authSafe']['content']->value);
        $cms = ASN1::map($decoded, ASN1\Maps\AuthenticatedSafe::MAP);

        foreach ($cms as $key=>$content) {
            switch ($content['contentType']) {
                case 'id-data': // id-data from CMS specs
                    $decoded = ASN1::decodeBER((string) $content['content']);
                    $cms[$key]['content'] = ASN1::map($decoded, ASN1\Maps\SafeContents::MAP);
                    $cms[$key]['content']->parent = $cms[$key];
                    foreach ($cms[$key]['content'] as $subkey=>$value) {
                        try {
                            $cms[$key]['content'][$subkey]['bagValue'] = match ("$value[bagId]") {
                                'PKCS8ShroudedKeyBag' => PublicKeyLoader::load("$value[bagValue]", $password),
                                'KeyBag' => PublicKeyLoader::load("$value[bagValue]"),
                                'CertBag' => self::handleCertBag("$value[bagValue]"),
                                default => $value['bagValue']
                            };
                        } catch (\Exception $e) {
                        }
                    }
                    break;
                case 'id-encryptedData':
                    if (!isset($password)) {
                        throw new NoPasswordProvidedException('Encrypted data was found, however, no password has been provided');
                    }
                    $decoded = ASN1::decodeBER((string) $content['content']);
                    $content = ASN1::map($decoded, ASN1\Maps\CMSEncryptedData::MAP);
                    $cipher = self::getCryptoObjectFromAlgorithmIdentifier($content['encryptedContentInfo']['contentEncryptionAlgorithm'], $password);
                    $content = $cipher->decrypt((string) $content['encryptedContentInfo']['encryptedContent']);
                    $decoded = ASN1::decodeBER($content);
                    $contents = ASN1::map($decoded, ASN1\Maps\SafeContents::MAP);

                    foreach ($contents as $content) {
                        if ($content['bagId'] == 'CertBag') {
                            $content['bagValue'] = self::handleCertBag($content['bagValue']->value);
                        }
                    }
                    $cms[$key]['content'] = $contents;
            }
        }

        $pfx['authSafe']['content'] = $cms;
        $pfx['authSafe']['content']->parent = $pfx['authSafe'];

        ASN1::enableCacheInvalidation();

        return $pfx;
    }

    /**
     * Sets the default hash algorithm
     */
    public static function setHashAlgorithm(string $algo): void
    {
        switch (strtolower($algo)) {
            case 'md2':
            case 'md5':
            case 'sha1':
            case 'sha224':
            case 'sha256':
            case 'sha384':
            case 'sha512/224':
            case 'sha512/256':
                break;
            default:
                throw new UnsupportedAlgorithmException("$algo is an unsupported hash algorithm");
        }
        self::$defaultHashAlgorithm = $algo;
    }

    /**
     * Sets the iteration count
     */
    public static function setIterationCount(int $count): void
    {
        self::$defaultIterationCount = $count;
    }

    /**
     * Sets the salt length
     */
    public static function setSaltLength(int $length): void
    {
        self::$defaultSaltLength = $length;
    }

    // PrivateKey objects are designed to be immutable hence their use of withPassword()
    // PFX is *not* designed to be immutable
    public function setPassword(?string $password = null): void
    {
        if (!isset($password)) {
            $this->removePassword();
            return;
        }
        if (isset($this->password)) { // there already is a password; simply changing the password is sufficient
            foreach ($this->pfx['authSafe']['content'] as $key=>$value) {
                $value = &$this->pfx['authSafe']['content'][$key];
                switch ($value['contentType']) {
                    case 'id-data':
                        foreach ($value['content'] as $subkey=>$subvalue) {
                            $subvalue = &$value['content'][$subkey];
                            if ($subvalue['bagId'] == 'PKCS8ShroudedKeyBag') {
                                $subvalue['bagValue'] = $subvalue['bagValue']->withPassword($password);
                            }
                            unset($subvalue);
                        }
                }
                unset($value);
            }
        } else { // there is no password but there will be; CertBag's need to be moved around
            $certs = $friendlyNames = $localKeyIDs = [];
            foreach ($this->pfx['authSafe']['content'] as $key=>$value) {
                $value = &$this->pfx['authSafe']['content'][$key];
                if ($value['contentType'] == 'id-encryptedData') {
                    throw new UnexpectedValueException('Found id-encryptedData in an unencrypted PFX file');
                }
                if ($value['contentType'] != 'id-data') {
                    throw new UnexpectedValueException("Found $value[contentType], expected id-data");
                }
                $numCertBags = 0;
                foreach ($value['content'] as $subkey=>$subvalue) {
                    $subvalue = &$value['content'][$subkey];
                    switch ($subvalue['bagId']) {
                        case 'PKCS8ShroudedKeyBag':
                            throw new UnexpectedValueException('Found PKCS8ShroudedKeyBag in an unencrypted PFX file');
                        case 'KeyBag':
                            $subvalue['bagId'] = 'PKCS8ShroudedKeyBag';
                            $subvalue['bagValue'] = $subvalue['bagValue']->withPassword($password);
                            break;
                        case 'CertBag':
                            $numCertBags++;
                    }
                    unset($subvalue);
                }
                if ($numCertBags == count($value['content'])) {
                    $value['contentType'] = 'id-encryptedData';
                    continue;
                }
                foreach ($value['content'] as $subkey=>$subvalue) {
                    $subvalue = $value['content'][$subkey];
                    if ($subvalue['bagId'] == 'CertBag') {
                        foreach ($subvalue['bagAttributes'] as $attr) {
                            switch ($attr['type']) {
                                case 'pkcs-9-at-localKeyId':
                                    $var = 'localKeyIDs';
                                    break;
                                case 'pkcs-9-at-friendlyName':
                                    $var = 'friendlyNames';
                                    break;
                                default:
                                    continue 2;
                            }
                            foreach ($attr['value'] as $attrValue) {
                                $$var[count($certs)][] = $attrValue;
                            }
                        }
                        $certs[] = $subvalue['bagValue']['certValue'];
                        unset($value['content'][$subkey]);
                    }
                }
                if ($numCertBags) {
                    if ($value['content'] instanceof Constructed) {
                        $value['content']->rekey();
                    } else {
                        $value['content'] = array_values($value['content']);
                    }
                }
                unset($value);
            }
            foreach ($certs as $i=>$cert) {
                $this->add($cert, friendlyName: $friendlyNames[$i], localKeyID: $localKeyIDs[$i]);
            }
        }
        $this->password = $password;
    }

    public function removePassword(): void
    {
        if (!isset($this->password)) {
            return;
        }

        $this->password = null;

        foreach ($this->pfx['authSafe']['content'] as $key=>$value) {
            $value = &$this->pfx['authSafe']['content'][$key];
            switch ($value['contentType']) {
                case 'id-data':
                    foreach ($value['content'] as $subkey=>$subvalue) {
                        $subvalue = &$value['content'][$subkey];
                        if ($subvalue['bagId'] == 'PKCS8ShroudedKeyBag') {
                            $subvalue['bagId'] = 'KeyBag';
                            $subvalue['bagValue'] = $subvalue['bagValue']->withoutPassword();
                        }
                        unset($subvalue);
                    }
                    break;
                case 'id-encryptedData':
                    $value['contentType'] = 'id-data';
            }
            unset($value);
        }
        unset($this->pfx['macData']);
    }

    /**
     * @var string|BaseString|string[]|BaseString[]|null $friendlyName
     * @var string|BaseString|string[]|BaseString[]|null $localKeyID
     */
    public function add(
        X509|PrivateKey $obj,
        string|BaseString|array|null $friendlyName = null,
        string|BaseString|array|null $localKeyID = null
    ): void
    {
        $extra = [];
        if (isset($friendlyName) || isset($localKeyID)) {
            if (isset($friendlyName)) {
                if (!is_array($friendlyName)) {
                    $value = [$friendlyName];
                } else {
                    foreach ($friendlyName as $temp) {
                        if (!is_string($temp) && !$temp instanceof BaseString) {
                            throw new UnexpectedValueException('Arrays must contain either strings or instances of BaseString');
                        }
                    }
                    $value = $friendlyName;
                }
                if (count($value)) {
                    $extra['bagAttributes'][] = [
                        'type' => 'pkcs-9-at-friendlyName',
                        'value' => $value,
                    ];
                }
            }
            if (isset($localKeyID)) {
                if (!is_array($localKeyID)) {
                    $value = [$localKeyID];
                } else {
                    foreach ($localKeyID as $temp) {
                        if (!is_string($temp) && !$temp instanceof BaseString) {
                            throw new UnexpectedValueException('Arrays must contain either strings or instances of BaseString');
                        }
                    }
                    $value = $localKeyID;
                }
                if (count($value)) {
                    $extra['bagAttributes'][] = [
                        'type' => 'pkcs-9-at-localKeyId',
                        'value' => $value,
                    ];
                }
            }
        }
        if ($obj instanceof PrivateKey) {
            if (isset($this->password)) {
                $obj = [
                    'bagId' => 'PKCS8ShroudedKeyBag',
                    'bagValue' => $obj->withPassword($this->password),
                ] + $extra;
            } else {
                $obj = [
                    'bagId' => 'KeyBag',
                    'bagValue' => $obj->withoutPassword(),
                ] + $extra;
            }
            $this->pfx['authSafe']['content'][] = [
                'contentType' => 'id-data',
                'content' => [$obj]
            ];
        } else {
            $obj = [
                'bagId' => 'CertBag',
                'bagValue' => [
                    'certId' => 'x509Certificate',
                    'certValue' => $obj,
                ]
            ] + $extra;
            $this->pfx['authSafe']['content'][] = [
                'contentType' => isset($this->password) ? 'id-encryptedData' : 'id-data',
                'content' => [$obj]
            ];
        }
    }

    public function toString(array $options = []): string
    {
        foreach ($this->pfx['authSafe']['content'] as $key=>$value) {
            $value = &$this->pfx['authSafe']['content'][$key];
            switch ($value['contentType']) {
                case 'id-data':
                    foreach ($value['content'] as $subkey=>$subvalue) {
                        $subvalue = &$value['content'][$subkey];
                        switch ($subvalue['bagId']) {
                            case 'CertBag':
                                $subvalue['bagValue']['certValue'] = new OctetString($subvalue['bagValue']['certValue']->getEncoded());
                                $subvalue['bagValue'] = new Element(ASN1::encodeDER($subvalue['bagValue'], Maps\CertBag::MAP));
                                break;
                            case 'KeyBag':
                            case 'PKCS8ShroudedKeyBag':
                                $subvalue['bagValue'] = new Element($subvalue['bagValue']->toString('PKCS8', ['binary' => true]));
                        }
                        $subvalue = new Element(ASN1::encodeDER($subvalue, Maps\SafeBag::MAP));
                        unset($subvalue);
                    }
                    $value['content'] = new OctetString(ASN1::encodeDER($value['content'], Maps\AuthenticatedSafe::MAP));
                    break;
                case 'id-encryptedData':
                    $crypt = self::getCryptoObjectFromParams($this->password, $options);
                    foreach ($value['content'] as $subkey=>$subvalue) {
                        $subvalue = &$value['content'][$subkey];
                        if ($subvalue['bagId'] != 'CertBag') {
                            break;
                        }
                        $subvalue['bagValue']['certValue'] = new OctetString($subvalue['bagValue']['certValue']->getEncoded());
                        $subvalue['bagValue'] = new Element(ASN1::encodeDER($subvalue['bagValue'], Maps\CertBag::MAP));
                        $subvalue = new Element(ASN1::encodeDER($subvalue, Maps\SafeBag::MAP));
                        unset($subvalue);
                    }
                    $value['content'] = ASN1::encodeDER($value['content'], Maps\SafeContents::MAP);
                    $value['content'] = new OctetString($crypt->encrypt($value['content']));
                    $value['content'] = [
                        'version' => 'v0',
                        'encryptedContentInfo' => [
                            'contentType' => 'id-data',
                            'contentEncryptionAlgorithm' => $crypt->getMetaData('algorithmIdentifier'),
                            'encryptedContent' => $value['content'],
                        ],
                    ];
                    $value['content'] = new Element(ASN1::encodeDER($value['content'], Maps\CMSEncryptedData::MAP));
            }
            unset($value);
        }

        $this->pfx['authSafe']['content'] = new OctetString(ASN1::encodeDER($this->pfx['authSafe']['content'], Maps\AuthenticatedSafe::MAP));

        $hashAlgorithm = $options['hashAlgorithm'] ?? self::$defaultHashAlgorithm;
        $saltLength = $options['saltLength'] ?? self::$defaultSaltLength;
        $iterationCount = $options['iterationCount'] ?? self::$defaultIterationCount;
        if ($hashAlgorithm && $this->password) {
            $salt = Random::string($saltLength);
            $hash = new Hash($hashAlgorithm);
            $hash->setPassword($this->password, $salt, $iterationCount);
            $mac = $hash->hash($this->pfx['authSafe']['content']->value);
            $this->pfx['macData'] = [
                'mac' => [
                    'digestAlgorithm' => [
                        'algorithm' => 'id-' . $hashAlgorithm,
                        'parameters' => null,
                    ],
                    'digest' => $mac,
                ],
                'macSalt' => $salt,
                'iterations' => $iterationCount,
            ];
        }

        $output = ASN1::encodeDER($this->pfx, Maps\PFX::MAP);

        $temp = self::load($output, $this->password);
        $this->pfx = $temp->pfx;

        return $output;
    }

    public function toArray(): array
    {
        $this->compile();
        return $this->pfx instanceof Constructed ? $this->pfx->toArray() : $this->pfx;
    }

    private static function handleCertBag(string $value): Constructed
    {
        $decoded = ASN1::decodeBER($value);
        $result = ASN1::map($decoded, ASN1\Maps\CertBag::MAP);
        if ($result['certId'] == 'x509Certificate') {
            $result['certValue'] = X509::load((string) $result['certValue']);
        }
        return $result;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function &offsetGet(mixed $offset): mixed
    {
        $this->compile();
        return $this->pfx[$offset];
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->pfx[$offset]);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->pfx[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->pfx[$offset]);
    }

    public function count(): int
    {
        return is_array($this->pfx) ? count($this->pfx) : $this->pfx->count();
    }

    public function rewind(): void
    {
        $this->compile();
        $this->pfx->rewind();
    }

    public function current(): mixed
    {
        $this->compile();
        return $this->pfx->current();
    }

    public function key(): mixed
    {
        $this->compile();
        return $this->pfx->key();
    }

    public function next(): void
    {
        $this->compile();
        $this->pfx->next();
    }

    public function valid(): bool
    {
        $this->compile();
        return $this->pfx->valid();
    }

    public function keys(): array
    {
        return $this->pfx instanceof Constructed ? $this->pfx->keys() : array_keys($this->pfx);
    }

    public function __debugInfo(): array
    {
        $this->compile();
        return $this->pfx->__debugInfo();
    }

    public function getEncoded(): string
    {
        $this->compile();
        return $this->toString();
    }

    private function compile(): void
    {
        if (!$this->pfx instanceof Constructed) {
            $temp = self::load("$this", $this->password);
            $this->pfx = $temp->pfx;
        }
        if ($this->pfx->hasEncoded()) {
            return;
        }
        $temp = self::load("$this");
        $this->pfx = $temp->pfx;
    }

    private function getNames(string $type): array
    {
        $names = [];

        foreach ($this->pfx['authSafe']['content'] as $key=>$value) {
            $value = $this->pfx['authSafe']['content'][$key];
            foreach ($value['content'] as $subkey=>$subvalue) {
                $subvalue = $value['content'][$subkey];
                if (isset($subvalue['bagAttributes'])) {
                    foreach ($subvalue['bagAttributes'] as $attr) {
                        if ($attr['type'] == $type) {
                            foreach ($attr['value'] as $subattr) {
                                $names[] = $subattr;
                            }
                        }
                    }
                }
            }
        }

        return array_values(array_unique($names));
    }

    public function getFriendlyNames(): array
    {
        return $this->getNames('pkcs-9-at-friendlyName');
    }

    public function getLocalKeyIDs(): array
    {
        return $this->getNames('pkcs-9-at-localKeyId');
    }

    private function pluck(?string $type = null, string|BaseString|null $search = null): array
    {
        $objects = [];

        foreach ($this->pfx['authSafe']['content'] as $key=>$value) {
            $value = $this->pfx['authSafe']['content'][$key];
            foreach ($value['content'] as $subkey=>$subvalue) {
                if (isset($type)) {
                    if (!isset($subvalue['bagAttributes'])) {
                        continue;
                    }
                    $matchFound = false;
                    foreach ($subvalue['bagAttributes'] as $attr) {
                        if ($attr['type'] == $type) {
                            foreach ($attr['value'] as $subattr) {
                                if (is_string($search) || $search::CLASS == $subattr::CLASS) {
                                    if ($subattr instanceof BaseString) {
                                        if ($subattr->isConvertable()) {
                                            $subattr = $subattr->toUTF8String();
                                        }
                                    }
                                    if ("$subattr" == "$search") {
                                        $matchFound = true;
                                    }
                                }
                            }
                        }
                    }
                    if (!$matchFound) {
                        continue;
                    }
                }
                $subvalue = $value['content'][$subkey];
                switch ($subvalue['bagId']) {
                    case 'KeyBag':
                    case 'PKCS8ShroudedKeyBag':
                        $objects[] = $subvalue['bagValue'];
                        break;
                    case 'CertBag':
                        $objects[] = $subvalue['bagValue']['certValue'];
                }
            }
        }

        return $objects;
    }

    public function getAll(): array
    {
        return $this->pluck();
    }

    public function getCertificates(): array
    {
        $arr = $this->getAll();
        $x509 = [];
        foreach ($arr as $el) {
            if ($el instanceof X509) {
                $x509[] = $el;
            }
        }
        return $x509;
    }

    public function getPrivateKeys(): array
    {
        $arr = $this->getAll();
        $keys = [];
        foreach ($arr as $el) {
            if ($el instanceof PrivateKey) {
                $keys[] = $el;
            }
        }
        return $keys;
    }

    public function pluckByFriendlyName(string|BaseString $value): array
    {
        return $this->pluck('pkcs-9-at-friendlyName', $value);
    }

    public function pluckByLocalKeyID(string|BaseString $value): array
    {
        return $this->pluck('pkcs-9-at-localKeyId', $value);
    }

    public function pfxFromFriendlyName(string|BaseString $value): self
    {
        $temp = new self();
        foreach ($this->pluckByFriendlyName($value) as $object) {
            $temp->add($object);
        }
        return $temp;
    }

    public function pfxFromLocalKeyID(string|BaseString $value): self
    {
        $temp = new self();
        foreach ($this->pluckByLocalKeyID($value) as $object) {
            $temp->add($object);
        }
        return $temp;
    }

    public function sign(string|Signable $source): string
    {
        $objects = $this->getAll();
        $message = 'Signatures can only be performed if there are *exactly* one private key and one matching X509 cert OR if there is just one private key, no more no less';
        if (count($objects) > 2 || !count($objects)) {
            throw new UnsupportedOperationException("$message - x1");
        }
        if (count($objects) == 1) {
            $private = $objects[0];
            if (!$private instanceof PrivateKey) {
                throw new UnsupportedOperationException("$message - x2");
            }
        } else {
            switch (true) {
                case $objects[0] instanceof PrivateKey && $objects[1] instanceof X509:
                    $private = $objects[0];
                    $public = $objects[1];
                    break;
                case $objects[0] instanceof X509 && $objects[1] instanceof PrivateKey:
                    $public = $objects[0];
                    $private = $objects[1];
                    break;
                default:
                    throw new UnsupportedOperationException("$message - x3");
            }
            $publicKey = (string) $public->getPublicKey();
            $privateKey = (string) $private->getPublicKey();
            if ($publicKey != $privateKey) {
                throw new UnsupportedOperationException("$message - x4");
            }
        }

        if (isset($public)) {
            if ($source instanceof X509 || $source instanceof CRL) {
                $source->setIssuerDN($public->getSubjectDN());
                $subjectKeyIdentifier = $public->getExtension('id-ce-subjectKeyIdentifier');
                if (isset($subjectKeyIdentifier)) {
                    $source->setAuthorityKeyIdentifier($subjectKeyIdentifier['extnValue']);
                }
            }
            // signing a CSR with a PFX doesn't quite make as much sense as signing an X509 or CRL does
            // but, regardless, this behavior is basically analgous to this:
            // $csr = new CSR($x509);
            // $private->sign($csr);
            if ($source instanceof CSR) {
                $source->setSubjectDN($public->getSubjectDN());
                $exts = array_unique($public->listExtensions());
                foreach ($exts as $name) {
                    $ext = $public->getExtension($name);
                    $source->setExtension($name, $ext['extnValue'], $ext['critical']);
                }
            }
        }
        $signature = $private->sign($source);

        return $signature;
    }
}