<?php

/**
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\MLDSA;

use phpseclib4\Crypt\{DSA, EC, MLDSA, PublicKeyLoader, RSA};
use phpseclib4\Crypt\MLDSA\Formats\Keys\PKCS8;
use phpseclib4\Crypt\MLDSA\{PrivateKey, PublicKey};
use phpseclib4\Exception\{
    BadConfigurationException,
    BadMethodCallException,
    LengthException,
    NoKeyLoadedException,
    PasswordNeededException,
    UnexpectedValueException,
    UnsupportedAlgorithmException,
    UnsupportedValueException
};
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Maps\OneAsymmetricKey;
use phpseclib4\File\ASN1\Types\ExplicitNull;
use phpseclib4\File\CSR;

/**
 * Key handling: everything here works without an ML-DSA engine
 */
class KeyTest extends TestCase
{
    public static function keyGenVectors(): array
    {
        return self::vectors('keyGen');
    }

    /**
     * The keyGen vectors that have the expanded private key (the first one of each parameter set)
     */
    public static function keyGenVectorsWithExpandedKey(): array
    {
        return self::vectors('keyGen', fn (array $case) => isset($case['sk']));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('keyGenVectors')]
    public function testSeedOnlyPrivateKey(array $case): void
    {
        $key = MLDSA::loadFormat('Raw', ['parameterSet' => $case['parameterSet'], 'seed' => $case['seed']]);
        $this->assertInstanceOf(PrivateKey::class, $key);
        $this->assertSame($case['parameterSet'], $key->getParameterSet());
        $this->assertSame(MLDSA::PARAMETER_SETS[$case['parameterSet']]['publicKey'] * 8, $key->getLength());

        // OneAsymmetricKey with the seed in the [0] IMPLICIT OCTET STRING of RFC 9881 and no parameters
        $der = $key->toString('PKCS8', ['binary' => true]);
        $this->assertSame(54, strlen($der));
        $this->assertSame("\x80\x20" . $case['seed'], substr($der, -34));

        $pem = $key->toString('PKCS8');
        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $pem);

        $key = PublicKeyLoader::load($pem);
        $this->assertInstanceOf(PrivateKey::class, $key);
        $this->assertSame($case['parameterSet'], $key->getParameterSet());
        $this->assertSame('PKCS8', $key->getLoadedFormat());
        $this->assertSame($pem, $key->toString('PKCS8'));

        $key = MLDSA::load($der);
        $this->assertSame($der, $key->toString('PKCS8', ['binary' => true]));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('keyGenVectorsWithExpandedKey')]
    public function testExpandedKeyPrivateKey(array $case): void
    {
        $key = MLDSA::loadFormat('Raw', ['parameterSet' => $case['parameterSet'], 'expandedKey' => $case['sk']]);
        $this->assertInstanceOf(PrivateKey::class, $key);

        // the expandedKey CHOICE is a plain OCTET STRING
        $der = $key->toString('PKCS8', ['binary' => true]);
        $this->assertStringEndsWith("\x04" . ASN1::encodeLength(strlen($case['sk'])) . $case['sk'], $der);
        $this->assertSame(strlen($case['sk']) + 28, strlen($der));

        $pem = $key->toString('PKCS8');
        $key = PublicKeyLoader::load($pem);
        $this->assertInstanceOf(PrivateKey::class, $key);
        $this->assertSame($case['parameterSet'], $key->getParameterSet());
        $this->assertSame($pem, $key->toString('PKCS8'));

        $components = PKCS8::load($pem);
        $this->assertSame($case['sk'], $components['expandedKey']);
        $this->assertArrayNotHasKey('seed', $components);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('keyGenVectorsWithExpandedKey')]
    public function testBothPrivateKey(array $case): void
    {
        $key = MLDSA::loadFormat('Raw', [
            'parameterSet' => $case['parameterSet'],
            'seed' => $case['seed'],
            'expandedKey' => $case['sk'],
        ]);
        $this->assertInstanceOf(PrivateKey::class, $key);

        // the both CHOICE is a SEQUENCE of two OCTET STRINGs
        $der = $key->toString('PKCS8', ['binary' => true]);
        $this->assertStringEndsWith("\x04\x20" . $case['seed'] . "\x04" . ASN1::encodeLength(strlen($case['sk'])) . $case['sk'], $der);
        $this->assertSame(strlen($case['sk']) + 66, strlen($der));

        // what was loaded is what's saved: both stays both
        $pem = $key->toString('PKCS8');
        $key = PublicKeyLoader::load($pem);
        $this->assertInstanceOf(PrivateKey::class, $key);
        $this->assertSame($pem, $key->toString('PKCS8'));

        $components = PKCS8::load($pem);
        $this->assertSame($case['seed'], $components['seed']);
        $this->assertSame($case['sk'], $components['expandedKey']);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('keyGenVectors')]
    public function testPublicKey(array $case): void
    {
        $key = MLDSA::loadFormat('Raw', ['parameterSet' => $case['parameterSet'], 'publicKey' => $case['pk']]);
        $this->assertInstanceOf(PublicKey::class, $key);
        $this->assertSame($case['parameterSet'], $key->getParameterSet());
        $this->assertSame(strlen($case['pk']) * 8, $key->getLength());

        // SubjectPublicKeyInfo: 22 bytes of ASN.1 around the raw public key, no parameters
        $der = $key->toString('PKCS8', ['binary' => true]);
        $this->assertSame(strlen($case['pk']) + 22, strlen($der));
        $this->assertStringEndsWith("\x00" . $case['pk'], $der);

        $pem = $key->toString('PKCS8');
        $this->assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $pem);

        $key = PublicKeyLoader::load($pem);
        $this->assertInstanceOf(PublicKey::class, $key);
        $this->assertSame($case['parameterSet'], $key->getParameterSet());
        $this->assertSame($pem, $key->toString('PKCS8'));

        $key = MLDSA::loadPublicKey($der);
        $this->assertSame($der, $key->toString('PKCS8', ['binary' => true]));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('keyGenVectorsWithExpandedKey')]
    public function testEncryptedPrivateKey(array $case): void
    {
        $key = MLDSA::loadFormat('Raw', ['parameterSet' => $case['parameterSet'], 'seed' => $case['seed']]);
        $plain = $key->toString('PKCS8');

        $encrypted = $key->withPassword('phpseclib')->toString('PKCS8');
        $this->assertStringStartsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----', $encrypted);

        $key = PublicKeyLoader::load($encrypted, 'phpseclib');
        $this->assertInstanceOf(PrivateKey::class, $key);
        $this->assertSame($plain, $key->withPassword()->toString('PKCS8'));
        // the password sticks to the loaded key
        $this->assertStringStartsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----', $key->toString('PKCS8'));

        $this->expectException(PasswordNeededException::class);
        PublicKeyLoader::load($encrypted);
    }

    public function testParameterSetNames(): void
    {
        $this->assertSame('ML-DSA-44', MLDSA::getParameterSetName('ML-DSA-44'));
        $this->assertSame('ML-DSA-65', MLDSA::getParameterSetName('ml-dsa-65'));
        $this->assertSame('ML-DSA-87', MLDSA::getParameterSetName('MLDSA87'));
        $this->assertSame('ML-DSA-44', MLDSA::getParameterSetName('mldsa44'));

        foreach (['ML-DSA-99', 'ML-DSA-4', 'ML-DSA', '44', 'Ed25519', 'ML-KEM-512'] as $name) {
            try {
                MLDSA::getParameterSetName($name);
                $this->fail("$name should not be a valid parameter set");
            } catch (UnsupportedAlgorithmException $e) {
                $this->assertStringContainsString('not a supported ML-DSA parameter set', $e->getMessage());
            }
        }

        $this->expectException(UnsupportedAlgorithmException::class);
        MLDSA::createKey('ML-DSA-99');
    }

    public function testRawKeyRejectsBadLengths(): void
    {
        try {
            MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44', 'seed' => str_repeat("\0", 31)]);
            $this->fail('A 31-byte seed should be rejected');
        } catch (LengthException $e) {
            $this->assertStringContainsString('seed should be 32 bytes long', $e->getMessage());
        }

        try {
            MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-65', 'publicKey' => str_repeat("\0", 1312)]);
            $this->fail('An ML-DSA-44 sized public key should be rejected for ML-DSA-65');
        } catch (LengthException $e) {
            $this->assertStringContainsString('publickey should be 1952 bytes long', $e->getMessage());
        }

        try {
            MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-87', 'expandedKey' => str_repeat("\0", 4032)]);
            $this->fail('An ML-DSA-65 sized expanded key should be rejected for ML-DSA-87');
        } catch (LengthException $e) {
            $this->assertStringContainsString('expandedkey should be 4896 bytes long', $e->getMessage());
        }

        $this->expectException(UnexpectedValueException::class);
        MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44']);
    }

    public function testPKCS8RejectsBadLengths(): void
    {
        $key = self::encodeOneAsymmetricKey('id-ml-dsa-44', "\x80\x1f" . str_repeat("\0", 31));
        try {
            PKCS8::load($key);
            $this->fail('A 31-byte seed should be rejected');
        } catch (LengthException $e) {
            $this->assertStringContainsString('seed should be 32 bytes long', $e->getMessage());
        }

        // a 32-byte seed labeled as an ML-DSA-65 expanded key
        $key = self::encodeOneAsymmetricKey('id-ml-dsa-65', "\x04\x20" . str_repeat("\0", 32));
        try {
            PKCS8::load($key);
            $this->fail('A 32-byte expanded key should be rejected');
        } catch (LengthException $e) {
            $this->assertStringContainsString('expanded private key should be 4032 bytes long', $e->getMessage());
        }

        // the generic loaders turn that into NoKeyLoadedException
        $this->expectException(NoKeyLoadedException::class);
        PublicKeyLoader::load($key);
    }

    public function testPKCS8RejectsParameters(): void
    {
        $key = self::encodeOneAsymmetricKey('id-ml-dsa-44', "\x80\x20" . str_repeat("\0", 32), new ExplicitNull());

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('must not have parameters');
        PKCS8::load($key);
    }

    public function testOtherAlgorithmsRejectMLDSAKeys(): void
    {
        $key = MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44', 'seed' => str_repeat("\0", 32)]);
        $pem = $key->toString('PKCS8');

        foreach ([EC::class, RSA::class, DSA::class] as $class) {
            try {
                $class::load($pem);
                $this->fail("$class should not load an ML-DSA key");
            } catch (NoKeyLoadedException $e) {
                $this->assertSame('Unable to read key', $e->getMessage());
            }
        }

        $this->expectException(NoKeyLoadedException::class);
        MLDSA::load(EC::createKey('Ed25519')->toString('PKCS8'));
    }

    public function testContext(): void
    {
        $key = MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44', 'seed' => str_repeat("\0", 32)]);

        $this->assertSame('phpseclib', $key->withContext('phpseclib')->getContext());
        $this->assertSame('', $key->withContext('')->getContext());
        $this->assertSame(255, strlen($key->withContext(str_repeat('c', 255))->getContext()));

        try {
            $key->withContext(str_repeat('c', 256));
            $this->fail('A 256-byte context should be rejected');
        } catch (LengthException $e) {
            $this->assertStringContainsString('255 bytes', $e->getMessage());
        }

        $this->expectException(BadMethodCallException::class);
        $key->withContext('phpseclib')->withContext(null)->getContext();
    }

    public function testHashCannotBeChanged(): void
    {
        $key = MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44', 'seed' => str_repeat("\0", 32)]);

        $this->expectException(BadMethodCallException::class);
        $this->assertInstanceOf(PrivateKey::class, $key->withHash('sha512'));
    }

    public function testNoFingerprint(): void
    {
        $key = MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44', 'publicKey' => str_repeat("\0", 1312)]);

        $this->expectException(UnsupportedValueException::class);
        $key->getFingerprint('sha256');
    }

    public function testSignableNotSupportedYet(): void
    {
        $key = MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44', 'seed' => str_repeat("\0", 32)]);

        $this->expectException(BadMethodCallException::class);
        $key->sign(new CSR());
    }

    /**
     * Without an engine keys can still be loaded and saved; everything else throws a clear exception
     */
    public function testUnsupportedRuntime(): void
    {
        $private = MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44', 'seed' => str_repeat("\0", 32)]);
        $public = MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44', 'publicKey' => str_repeat("\0", 1312)]);

        $property = new \ReflectionProperty(MLDSA::class, 'engineAvailable');
        $original = $property->getValue();
        $property->setValue(null, false);
        try {
            $this->assertFalse(MLDSA::isSupported());

            $operations = [
                'createKey' => fn () => MLDSA::createKey('ML-DSA-44'),
                'sign' => fn () => $private->sign('phpseclib'),
                'getPublicKey' => fn () => $private->getPublicKey(),
                'verify' => fn () => $public->verify('phpseclib', str_repeat("\0", 2420)),
            ];
            foreach ($operations as $name => $operation) {
                try {
                    $operation();
                    $this->fail("$name should throw an exception when there's no engine");
                } catch (BadConfigurationException $e) {
                    $this->assertStringContainsString('PHP 8.4+', $e->getMessage());
                    $this->assertStringContainsString('OpenSSL 3.5+', $e->getMessage());
                }
            }

            // loading and saving don't need an engine
            $this->assertInstanceOf(PrivateKey::class, PublicKeyLoader::load($private->toString('PKCS8')));
            $this->assertInstanceOf(PublicKey::class, PublicKeyLoader::load($public->toString('PKCS8')));
        } finally {
            $property->setValue(null, $original);
        }
    }

    public function testForcedEngines(): void
    {
        $private = MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44', 'seed' => str_repeat("\0", 32)]);
        $public = MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44', 'publicKey' => str_repeat("\0", 1312)]);

        try {
            foreach (['PHP', 'libsodium'] as $engine) {
                MLDSA::forceEngine($engine);
                $this->assertSame($engine, MLDSA::getForcedEngine());

                $operations = [
                    'createKey' => fn () => MLDSA::createKey('ML-DSA-44'),
                    'sign' => fn () => $private->sign('phpseclib'),
                    'getPublicKey' => fn () => $private->getPublicKey(),
                    'verify' => fn () => $public->verify('phpseclib', str_repeat("\0", 2420)),
                ];
                foreach ($operations as $name => $operation) {
                    try {
                        $operation();
                        $this->fail("$name should throw an exception when the $engine engine is forced");
                    } catch (BadConfigurationException $e) {
                        $this->assertSame("Engine $engine is forced but unsupported for ML-DSA (OpenSSL is the only ML-DSA engine)", $e->getMessage());
                    }
                }
            }

            // forcing the EC engine doesn't affect ML-DSA and vice versa
            EC::forceEngine('PHP');
            MLDSA::forceEngine(null);
            $this->assertSame('PHP', EC::getForcedEngine());
            $this->assertNull(MLDSA::getForcedEngine());

            $this->expectException(BadConfigurationException::class);
            MLDSA::forceEngine('GMP');
        } finally {
            EC::forceEngine(null);
            MLDSA::forceEngine(null);
        }
    }

    /**
     * DER encodes a OneAsymmetricKey with the given ML-DSA-PrivateKey content
     */
    private static function encodeOneAsymmetricKey(string $oid, string $privateKey, ?ExplicitNull $params = null): string
    {
        ASN1::loadOIDs(array_combine(PKCS8::OID_NAME, PKCS8::OID_VALUE));

        $key = [
            'version' => 'v1',
            'privateKeyAlgorithm' => ['algorithm' => $oid],
            'privateKey' => $privateKey,
        ];
        if (isset($params)) {
            $key['privateKeyAlgorithm']['parameters'] = $params;
        }

        return ASN1::encodeDER($key, OneAsymmetricKey::MAP);
    }
}
