<?php

/**
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\MLDSA;

use phpseclib4\Crypt\{MLDSA, PublicKeyLoader};
use phpseclib4\Crypt\MLDSA\{PrivateKey, PublicKey};
use phpseclib4\Exception\{BadConfigurationException, BadMethodCallException, NoKeyLoadedException, UnexpectedValueException};

class CreateKeyTest extends TestCase
{
    #[\PHPUnit\Framework\Attributes\DataProvider('parameterSets')]
    public function testCreateKey(string $parameterSet): void
    {
        if (!MLDSA::isSupported()) {
            $this->expectException(BadConfigurationException::class);
            $this->expectExceptionMessage('OpenSSL 3.5+');
            MLDSA::createKey($parameterSet);
            return;
        }

        $sizes = MLDSA::PARAMETER_SETS[$parameterSet];

        $private = MLDSA::createKey($parameterSet);
        $this->assertInstanceOf(PrivateKey::class, $private);
        $this->assertSame($parameterSet, $private->getParameterSet());
        $this->assertSame($sizes['publicKey'] * 8, $private->getLength());

        // the key is saved in the seed-only form of RFC 9881
        $der = $private->toString('PKCS8', ['binary' => true]);
        $this->assertSame(54, strlen($der));
        $this->assertSame("\x80\x20", substr($der, 20, 2));

        $public = $private->getPublicKey();
        $this->assertInstanceOf(PublicKey::class, $public);
        $this->assertSame($parameterSet, $public->getParameterSet());
        $this->assertSame($sizes['publicKey'] + 22, strlen($public->toString('PKCS8', ['binary' => true])));

        $message = random_bytes(1024);
        $signature = $private->sign($message);
        $this->assertSame($sizes['signature'], strlen($signature));
        $this->assertTrue($public->verify($message, $signature));

        // the saved key and the saved public key still work together
        $reloaded = PublicKeyLoader::load($private->toString('PKCS8'));
        $this->assertTrue(PublicKeyLoader::load($public->toString('PKCS8'))->verify($message, $reloaded->sign($message)));

        $this->assertFalse($public->verify($message . "\0", $signature));
        $this->assertFalse($public->verify(substr($message, 1), $signature));
        $this->assertFalse($public->verify('', $signature));

        $corrupted = $signature;
        $corrupted[100] = chr(ord($corrupted[100]) ^ 1);
        $this->assertFalse($public->verify($message, $corrupted));
        $this->assertFalse($public->verify($message, substr($signature, 0, -1)));
        $this->assertFalse($public->verify($message, $signature . "\0"));
        $this->assertFalse($public->verify($message, ''));

        // another key doesn't verify the signature
        $other = MLDSA::createKey($parameterSet);
        $this->assertNotSame($private->toString('PKCS8'), $other->toString('PKCS8'));
        $this->assertFalse($other->getPublicKey()->verify($message, $signature));

        // nor does a key with another parameter set (the signature has the wrong length for it)
        foreach (array_keys(MLDSA::PARAMETER_SETS) as $otherSet) {
            if ($otherSet != $parameterSet) {
                $this->assertFalse(MLDSA::createKey($otherSet)->getPublicKey()->verify($message, $signature));
            }
        }

        // created keys weren't loaded
        $this->expectException(NoKeyLoadedException::class);
        $private->getLoadedFormat();
    }

    public function testEmptyAndLargeMessages(): void
    {
        self::requireEngine();

        $private = MLDSA::createKey('ML-DSA-65');
        $public = $private->getPublicKey();

        $this->assertTrue($public->verify('', $private->sign('')));

        $message = random_bytes(1 << 20);
        $this->assertTrue($public->verify($message, $private->sign($message)));
    }

    public function testContextWithOpenSSLEngine(): void
    {
        self::requireEngine();

        $private = MLDSA::createKey('ML-DSA-44');
        $message = 'phpseclib';

        // the empty context is the default of FIPS 204 and the only one OpenSSL can do through ext/openssl
        $signature = $private->withContext('')->sign($message);
        $this->assertTrue($private->getPublicKey()->withContext('')->verify($message, $signature));

        $public = $private->withContext('ctx')->getPublicKey();
        $this->assertSame('ctx', $public->getContext());

        try {
            $private->withContext('ctx')->sign($message);
            $this->fail('Signing with a context should throw an exception');
        } catch (BadConfigurationException $e) {
            $this->assertStringContainsString('context strings', $e->getMessage());
        }

        $this->expectException(BadConfigurationException::class);
        $public->verify($message, $signature);
    }

    public function testSignatureMustBeAString(): void
    {
        self::requireEngine();

        $public = MLDSA::createKey('ML-DSA-44')->getPublicKey();

        $this->expectException(UnexpectedValueException::class);
        $public->verify('phpseclib', ['r' => '', 's' => '']);
    }

    public function testCreateKeyFromFinalClass(): void
    {
        $this->expectException(BadMethodCallException::class);
        PrivateKey::createKey('ML-DSA-44');
    }
}
