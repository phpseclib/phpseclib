<?php

/**
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\File\X509;

use phpseclib4\Crypt\MLDSA;
use phpseclib4\Crypt\MLDSA\{PrivateKey, PublicKey};
use phpseclib4\Exception\{UnexpectedValueException, UnsupportedAlgorithmException};
use phpseclib4\File\{CRL, CSR, X509};
use phpseclib4\Math\BigInteger;
use phpseclib4\Tests\PhpseclibTestCase;

/**
 * ML-DSA (RFC 9881) in X.509 certificates, CSRs and CRLs
 *
 * The files in the mldsa directory were made with the OpenSSL 4.0.3 command line tool (the commands are in
 * mldsa/README.md). Loading them needs no engine; signing and verifying need ext/openssl with OpenSSL 3.5+.
 */
class MLDSATest extends PhpseclibTestCase
{
    /**
     * DER encoding of the AlgorithmIdentifier of each parameter set: a SEQUENCE with the OID alone
     * (RFC 9881, section 3)
     */
    private const ALGORITHM_IDENTIFIERS = [
        'ML-DSA-44' => "\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x11",
        'ML-DSA-65' => "\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x12",
        'ML-DSA-87' => "\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x13",
    ];

    public static function parameterSets(): array
    {
        $sets = [];
        foreach (array_keys(MLDSA::PARAMETER_SETS) as $parameterSet) {
            $sets[$parameterSet] = [$parameterSet];
        }
        return $sets;
    }

    private static function fixture(string $name): string
    {
        return file_get_contents(__DIR__ . '/mldsa/' . $name);
    }

    private static function privateKey(string $parameterSet): PrivateKey
    {
        return MLDSA::loadPrivateKey(self::fixture("key-$parameterSet.pem"));
    }

    private static function requireEngine(): void
    {
        if (!MLDSA::isSupported()) {
            self::markTestSkipped('ML-DSA needs PHP 8.4+ with the OpenSSL extension built against OpenSSL 3.5+');
        }
    }

    /**
     * The OID of the parameter set, no parameters, and the exact DER bytes
     */
    private function assertAlgorithmIdentifier(string $parameterSet, mixed $algorithmIdentifier): void
    {
        $this->assertSame('id-' . strtolower($parameterSet), (string) $algorithmIdentifier['algorithm']);
        $this->assertFalse(isset($algorithmIdentifier['parameters']));
        $this->assertSame(self::ALGORITHM_IDENTIFIERS[$parameterSet], $algorithmIdentifier->getEncoded());
    }

    /**
     * No AlgorithmIdentifier in the DER has the OID followed by a NULL
     */
    private function assertNoNullParameters(string $parameterSet, string $der): void
    {
        $oid = substr(self::ALGORITHM_IDENTIFIERS[$parameterSet], 2);
        $this->assertStringContainsString($oid, $der);
        $this->assertStringNotContainsString($oid . "\x05\x00", $der);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('parameterSets')]
    public function testLoadSelfSigned(string $parameterSet): void
    {
        $x509 = X509::load(self::fixture("self-signed-$parameterSet.pem"));

        $this->assertAlgorithmIdentifier($parameterSet, $x509['tbsCertificate']['signature']);
        $this->assertAlgorithmIdentifier($parameterSet, $x509['signatureAlgorithm']);

        $publicKey = $x509->getPublicKey();
        $this->assertInstanceOf(PublicKey::class, $publicKey);
        $this->assertSame($parameterSet, $publicKey->getParameterSet());

        // the BIT STRING holds the raw ML-DSA signature, with no unused bits
        $signature = (string) $x509['signature'];
        $this->assertSame("\0", $signature[0]);
        $this->assertSame(MLDSA::PARAMETER_SETS[$parameterSet]['signature'], strlen($signature) - 1);

        // RFC 9881, section 5: at least one of digitalSignature, nonRepudiation, keyCertSign and cRLSign
        $keyUsage = $x509->getExtension('id-ce-keyUsage')['extnValue'];
        $this->assertTrue($keyUsage->contains('digitalSignature'));
        $this->assertTrue($keyUsage->contains('keyCertSign'));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('parameterSets')]
    public function testValidateSelfSigned(string $parameterSet): void
    {
        self::requireEngine();

        $x509 = X509::load(self::fixture("self-signed-$parameterSet.pem"));
        $this->assertTrue($x509->validateSignature(false));
    }

    public function testLoadLeaf(): void
    {
        $leaf = X509::load(self::fixture('leaf-ML-DSA-44.pem'));

        // an ML-DSA-44 key in a certificate signed by the ML-DSA-65 CA
        $this->assertSame('ML-DSA-44', $leaf->getPublicKey()->getParameterSet());
        $this->assertAlgorithmIdentifier('ML-DSA-65', $leaf['tbsCertificate']['signature']);
        $this->assertAlgorithmIdentifier('ML-DSA-65', $leaf['signatureAlgorithm']);
        $this->assertSame('O = phpseclib ML-DSA-65 self-signed', $leaf->getIssuerDN());
        $this->assertSame('CN = phpseclib ML-DSA-44 leaf', $leaf->getSubjectDN());
    }

    public function testValidateChain(): void
    {
        self::requireEngine();

        X509::clearCAStore();
        X509::addCA(self::fixture('self-signed-ML-DSA-65.pem'));
        try {
            $leaf = X509::load(self::fixture('leaf-ML-DSA-44.pem'));
            $this->assertTrue($leaf->validateSignature());
            $this->assertCount(2, $leaf->getValidationChain());

            // the CA of the leaf is not the CA of the other self-signed certificates
            $other = X509::load(self::fixture('self-signed-ML-DSA-44.pem'));
            $this->assertFalse($other->validateSignature());
        } finally {
            X509::clearCAStore();
        }
    }

    public function testTamperedSignature(): void
    {
        self::requireEngine();

        $x509 = X509::load(self::fixture('self-signed-ML-DSA-44.pem'));
        $signature = substr((string) $x509['signature'], 1);
        $signature[100] = chr(ord($signature[100]) ^ 1);
        $x509->setSignature($signature);

        $x509 = X509::load("$x509");
        $this->assertFalse($x509->validateSignature(false));
    }

    /**
     * RFC 9881, section 3: the parameters MUST be absent. The fixture has a NULL in both AlgorithmIdentifiers
     * and is otherwise valid (it is the ML-DSA-44 self-signed certificate, re-signed). No engine is needed
     * since the check comes before the verification.
     */
    public function testParametersMustBeAbsent(): void
    {
        $x509 = X509::load(self::fixture('null-params-ML-DSA-44.pem'));
        $this->assertTrue(isset($x509['tbsCertificate']['signature']['parameters']));
        $this->assertTrue(isset($x509['signatureAlgorithm']['parameters']));

        $this->expectException(UnexpectedValueException::class);
        $x509->validateSignature(false);
    }

    /**
     * The signature algorithm OID has to match the parameter set of the signing key
     */
    public function testAlgorithmMustMatchTheKey(): void
    {
        $x509 = X509::load(self::fixture('self-signed-ML-DSA-44.pem'));
        $x509['signatureAlgorithm']['algorithm'] = 'id-ml-dsa-65';

        $this->expectException(UnsupportedAlgorithmException::class);
        $x509->validateSignature(false);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('parameterSets')]
    public function testSignSelfSigned(string $parameterSet): void
    {
        self::requireEngine();

        $private = self::privateKey($parameterSet);

        $x509 = new X509($private->getPublicKey());
        $x509->setDN("O=phpseclib $parameterSet self-signed");
        $x509->setEndDate('+10 years');
        $x509->makeCA();
        $private->sign($x509);

        $der = $x509->toString(['binary' => true]);
        $this->assertAlgorithmIdentifier($parameterSet, $x509['tbsCertificate']['signature']);
        $this->assertAlgorithmIdentifier($parameterSet, $x509['signatureAlgorithm']);
        $this->assertNoNullParameters($parameterSet, $der);

        $x509 = X509::load($der);
        $this->assertSame($parameterSet, $x509->getPublicKey()->getParameterSet());
        $this->assertTrue($x509->validateSignature(false));

        // the engine is ext/openssl, so it can check the certificate as a whole too
        $this->assertSame(1, openssl_x509_verify("$x509", openssl_pkey_get_public("$x509")));
    }

    public function testSignWithCA(): void
    {
        self::requireEngine();

        $ca = X509::load(self::fixture('self-signed-ML-DSA-65.pem'));
        $caKey = self::privateKey('ML-DSA-65');

        $x509 = new X509(CSR::load(self::fixture('csr-ML-DSA-44.pem')));
        $x509->setIssuerDN($ca->getSubjectDN(X509::DN_ARRAY));
        $x509->setAuthorityKeyIdentifier($ca->getExtension('id-ce-subjectKeyIdentifier')['extnValue']);
        $caKey->sign($x509);

        $this->assertAlgorithmIdentifier('ML-DSA-65', $x509['tbsCertificate']['signature']);
        $this->assertAlgorithmIdentifier('ML-DSA-65', $x509['signatureAlgorithm']);

        $x509 = X509::load("$x509");
        $this->assertSame('ML-DSA-44', $x509->getPublicKey()->getParameterSet());
        $this->assertSame('CN = phpseclib ML-DSA-44 leaf', $x509->getSubjectDN());

        X509::clearCAStore();
        X509::addCA($ca);
        try {
            $this->assertTrue($x509->validateSignature());
        } finally {
            X509::clearCAStore();
        }

        $this->assertSame(1, openssl_x509_verify("$x509", openssl_pkey_get_public("$ca")));
    }

    public function testLoadCSR(): void
    {
        $csr = CSR::load(self::fixture('csr-ML-DSA-44.pem'));

        $this->assertAlgorithmIdentifier('ML-DSA-44', $csr['signatureAlgorithm']);
        $this->assertInstanceOf(PublicKey::class, $csr->getPublicKey());
        $this->assertSame('CN = phpseclib ML-DSA-44 leaf', $csr->getDN());
    }

    public function testValidateCSR(): void
    {
        self::requireEngine();

        $csr = CSR::load(self::fixture('csr-ML-DSA-44.pem'));
        $this->assertTrue($csr->validateSignature());
    }

    public function testSignCSR(): void
    {
        self::requireEngine();

        $private = self::privateKey('ML-DSA-44');

        $csr = new CSR($private->getPublicKey());
        $csr->setDN('CN=phpseclib ML-DSA-44 CSR');
        $private->sign($csr);

        $this->assertAlgorithmIdentifier('ML-DSA-44', $csr['signatureAlgorithm']);
        $this->assertNoNullParameters('ML-DSA-44', $csr->toString(['binary' => true]));

        $csr = CSR::load("$csr");
        $this->assertSame('ML-DSA-44', $csr->getPublicKey()->getParameterSet());
        $this->assertTrue($csr->validateSignature());

        // without a public key the one of the signing key is used
        $csr = new CSR();
        $csr->setDN('CN=phpseclib ML-DSA-44 CSR');
        $private->sign($csr);

        $csr = CSR::load("$csr");
        $this->assertSame('ML-DSA-44', $csr->getPublicKey()->getParameterSet());
        $this->assertTrue($csr->validateSignature());
    }

    public function testLoadCRL(): void
    {
        $crl = CRL::load(self::fixture('crl-ML-DSA-65.pem'));
        $leaf = X509::load(self::fixture('leaf-ML-DSA-44.pem'));

        $this->assertAlgorithmIdentifier('ML-DSA-65', $crl['tbsCertList']['signature']);
        $this->assertAlgorithmIdentifier('ML-DSA-65', $crl['signatureAlgorithm']);
        $this->assertSame('O = phpseclib ML-DSA-65 self-signed', $crl->getIssuerDN());
        $this->assertSame(1, $crl->numRevoked());
        $this->assertTrue($crl->isRevoked($leaf));
        $this->assertSame('keyCompromise', (string) $crl->getRevokedExtension($leaf, 'id-ce-cRLReasons')['extnValue']);
    }

    public function testValidateCRL(): void
    {
        self::requireEngine();

        X509::clearCAStore();
        X509::addCA(self::fixture('self-signed-ML-DSA-65.pem'));
        try {
            $crl = CRL::load(self::fixture('crl-ML-DSA-65.pem'));
            $this->assertTrue($crl->validateSignature());
        } finally {
            X509::clearCAStore();
        }
    }

    public function testSignCRL(): void
    {
        self::requireEngine();

        $ca = X509::load(self::fixture('self-signed-ML-DSA-65.pem'));
        $caKey = self::privateKey('ML-DSA-65');

        $crl = new CRL();
        $crl->revoke(new BigInteger('1234'), 'keyCompromise', '+1 year');
        $crl->setDN($ca->getDN());
        $crl->setAuthorityKeyIdentifier($ca->getExtension('id-ce-subjectKeyIdentifier')['extnValue']);
        $caKey->sign($crl);

        $this->assertAlgorithmIdentifier('ML-DSA-65', $crl['tbsCertList']['signature']);
        $this->assertAlgorithmIdentifier('ML-DSA-65', $crl['signatureAlgorithm']);
        $this->assertNoNullParameters('ML-DSA-65', $crl->toString(['binary' => true]));

        X509::clearCAStore();
        X509::addCA($ca);
        try {
            $crl = CRL::load("$crl");
            $this->assertTrue($crl->isRevoked(new BigInteger('1234')));
            $this->assertTrue($crl->validateSignature());
        } finally {
            X509::clearCAStore();
        }
    }
}
