<?php

/**
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\File\CMS;

use phpseclib4\Crypt\MLDSA;
use phpseclib4\Crypt\MLDSA\PublicKey;
use phpseclib4\File\CMS;
use phpseclib4\File\CMS\SignedData;
use phpseclib4\File\X509;
use phpseclib4\Tests\PhpseclibTestCase;

/**
 * ML-DSA (RFC 9882) in CMS SignedData
 *
 * The fixtures are the ones of tests/Unit/File/X509/mldsa (see the README.md there): cms-ML-DSA-44.pem was
 * signed by the ML-DSA-44 leaf with SHA-512 as the digest, which is the one every parameter set has to support.
 */
class MLDSATest extends PhpseclibTestCase
{
    private const MESSAGE = "ML-DSA in CMS: signed by the ML-DSA-44 leaf, digest SHA-512\n";

    private static function fixture(string $name): string
    {
        return file_get_contents(__DIR__ . '/../X509/mldsa/' . $name);
    }

    private static function requireEngine(): void
    {
        if (!MLDSA::isSupported()) {
            self::markTestSkipped('ML-DSA needs PHP 8.4+ with the OpenSSL extension built against OpenSSL 3.5+');
        }
    }

    public function testLoadOpenSSLSignedData(): void
    {
        $cms = CMS::load(self::fixture('cms-ML-DSA-44.pem'));
        $this->assertInstanceOf(SignedData::class, $cms);
        $this->assertSame(self::MESSAGE, (string) $cms['content']['encapContentInfo']['eContent']);

        $signers = $cms->getSigners();
        $this->assertCount(1, $signers);
        $this->assertSame('id-ml-dsa-44', (string) $signers[0]['signatureAlgorithm']['algorithm']);
        $this->assertFalse(isset($signers[0]['signatureAlgorithm']['parameters']));
        $this->assertSame('id-sha512', (string) $signers[0]['digestAlgorithm']['algorithm']);
        $this->assertSame(MLDSA::PARAMETER_SETS['ML-DSA-44']['signature'], strlen((string) $signers[0]['signature']));

        $certs = $cms->getCertificates();
        $this->assertCount(1, $certs);
        $this->assertInstanceOf(PublicKey::class, $certs[0]->getPublicKey());
        $this->assertSame('CN = phpseclib ML-DSA-44 leaf', $certs[0]->getSubjectDN());
    }

    public function testValidateOpenSSLSignedData(): void
    {
        self::requireEngine();

        X509::clearCAStore();
        X509::addCA(self::fixture('self-signed-ML-DSA-65.pem'));
        try {
            $cms = CMS::load(self::fixture('cms-ML-DSA-44.pem'));
            $this->assertTrue($cms->validateSignature());

            // a changed content no longer matches the message digest
            $cms->attach(rtrim(self::MESSAGE));
            $this->assertFalse($cms->validateSignature());
        } finally {
            X509::clearCAStore();
        }
    }

    public function testSignWithPrivateKey(): void
    {
        self::requireEngine();

        $private = MLDSA::loadPrivateKey(self::fixture('key-ML-DSA-65.pem'));

        $cms = new SignedData('hello, world!');
        $private->sign($cms);

        $signer = $cms->getSigners()[0];
        $this->assertSame('id-ml-dsa-65', (string) $signer['signatureAlgorithm']['algorithm']);
        $this->assertFalse(isset($signer['signatureAlgorithm']['parameters']));
        // RFC 9882, section 3.3
        $this->assertSame('id-sha512', (string) $signer['digestAlgorithm']['algorithm']);
        $this->assertSame('ML-DSA-65', $signer->getCertificate()->getPublicKey()->getParameterSet());

        $cms = CMS::load("$cms");
        $this->assertTrue($cms->validateSignature(false));
    }

    /**
     * What the library signs has to verify with ext/openssl as well
     */
    public function testOpenSSLVerifiesSignedData(): void
    {
        self::requireEngine();
        if (!function_exists('openssl_cms_verify')) {
            self::markTestSkipped('openssl_cms_verify() not available');
        }

        $private = MLDSA::loadPrivateKey(self::fixture('key-ML-DSA-44.pem'));
        $leaf = X509::load(self::fixture('leaf-ML-DSA-44.pem'));

        $cms = new SignedData(self::MESSAGE);
        $signer = $cms->addSigner($leaf);
        $private->sign($signer);

        $input = $this->createTempFile();
        $ca = $this->createTempFile();
        $output = $this->createTempFile();
        file_put_contents($input, "$cms");
        file_put_contents($ca, self::fixture('self-signed-ML-DSA-65.pem'));

        $result = openssl_cms_verify(
            input_filename: $input,
            flags: OPENSSL_CMS_BINARY,
            ca_info: [$ca],
            content: $output,
            encoding: OPENSSL_ENCODING_PEM
        );
        $this->assertTrue($result, 'openssl_cms_verify() was unable to verify the signature: ' . openssl_error_string());
        $this->assertSame(self::MESSAGE, file_get_contents($output));
    }
}
