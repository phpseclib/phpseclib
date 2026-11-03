<?php

/**
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\MLDSA;

use phpseclib4\Crypt\MLDSA;
use phpseclib4\Crypt\MLDSA\Formats\Keys\PKCS8;
use phpseclib4\Crypt\MLDSA\{PrivateKey, PublicKey};

/**
 * Known answer tests with the NIST ACVP vectors (acvp-ML-DSA-FIPS204.json)
 *
 * What the OpenSSL engine can be checked against: the public key derived from a seed or from an
 * expanded private key, the verification of the NIST signatures (pure ML-DSA, empty context) and
 * the sigVer verdicts. What it can't: signature bytes (openssl_sign() only makes hedged signatures),
 * context strings (openssl_sign() / openssl_verify() can't take one) and HashML-DSA (not in OpenSSL).
 * Those vectors are in the fixture already and their tests are skipped until there's a pure-PHP engine.
 */
class KnownAnswerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        self::requireEngine();
    }

    public static function keyGenVectors(): array
    {
        return self::vectors('keyGen');
    }

    public static function keyGenVectorsWithExpandedKey(): array
    {
        return self::vectors('keyGen', fn (array $case) => isset($case['sk']));
    }

    public static function sigGenVectors(): array
    {
        return self::vectors('sigGen', fn (array $case) => $case['opensslTestable']);
    }

    public static function sigGenVectorsWithContext(): array
    {
        return self::vectors('sigGen', fn (array $case) => $case['context'] !== '');
    }

    public static function sigVerVectors(): array
    {
        return self::vectors('sigVer', fn (array $case) => $case['opensslTestable']);
    }

    public static function sigVerVectorsWithContext(): array
    {
        return self::vectors('sigVer', fn (array $case) => $case['preHash'] == 'pure' && $case['context'] !== '');
    }

    public static function sigVerPreHashVectors(): array
    {
        return self::vectors('sigVer', fn (array $case) => $case['preHash'] == 'preHash');
    }

    /**
     * ML-DSA.KeyGen: the public key derived from the seed is the one NIST expects
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('keyGenVectors')]
    public function testKeyGen(array $case): void
    {
        $private = MLDSA::loadFormat('Raw', ['parameterSet' => $case['parameterSet'], 'seed' => $case['seed']]);
        $this->assertInstanceOf(PrivateKey::class, $private);

        $public = $private->getPublicKey();
        $this->assertInstanceOf(PublicKey::class, $public);
        $this->assertSame($case['parameterSet'], $public->getParameterSet());

        $expected = PKCS8::savePublicKey($case['parameterSet'], $case['pk']);
        $this->assertSame($expected, $public->toString('PKCS8'));
        $this->assertStringEndsWith($case['pk'], $public->toString('PKCS8', ['binary' => true]));
    }

    /**
     * The expanded private key (sk) gives the same public key as the seed
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('keyGenVectorsWithExpandedKey')]
    public function testPublicKeyFromExpandedKey(array $case): void
    {
        $private = MLDSA::loadFormat('Raw', ['parameterSet' => $case['parameterSet'], 'expandedKey' => $case['sk']]);
        $public = $private->getPublicKey();
        $this->assertStringEndsWith($case['pk'], $public->toString('PKCS8', ['binary' => true]));

        $private = MLDSA::loadFormat('Raw', ['parameterSet' => $case['parameterSet'], 'seed' => $case['seed'], 'expandedKey' => $case['sk']]);
        $public = $private->getPublicKey();
        $this->assertStringEndsWith($case['pk'], $public->toString('PKCS8', ['binary' => true]));
    }

    /**
     * The seed expands to the expanded private key NIST expects
     *
     * phpseclib never expands the seed itself (it saves what it has) so this goes through
     * openssl_pkey_export(), which writes the both CHOICE of RFC 9881.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('keyGenVectorsWithExpandedKey')]
    public function testSeedExpansion(array $case): void
    {
        $private = MLDSA::loadFormat('Raw', ['parameterSet' => $case['parameterSet'], 'seed' => $case['seed']]);

        $key = openssl_pkey_get_private($private->toString('PKCS8'));
        $this->assertNotFalse($key);

        $exported = '';
        // the config file is the one RSA::createKey() uses; the system wide one might not be loadable
        $config = ['config' => dirname(__DIR__, 4) . '/phpseclib/openssl.cnf'];
        if (!openssl_pkey_export($key, $exported, null, $config)) {
            $error = openssl_error_string();
            while (openssl_error_string() !== false) {
            }
            self::markTestSkipped('openssl_pkey_export() does not work in this environment: ' . $error);
        }

        $components = PKCS8::load($exported);
        $this->assertSame($case['parameterSet'], $components['parameterSet']);
        $this->assertSame($case['seed'], $components['seed']);
        $this->assertSame($case['sk'], $components['expandedKey']);

        // and the exported key loads back into phpseclib as a both key (OpenSSL ends its PEMs with a newline)
        $this->assertSameNL(rtrim($exported), MLDSA::load($exported)->toString('PKCS8'));
    }

    /**
     * ML-DSA.Verify of the signatures NIST generated (pure ML-DSA, empty context)
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('sigGenVectors')]
    public function testSigGen(array $case): void
    {
        $private = MLDSA::loadFormat('Raw', ['parameterSet' => $case['parameterSet'], 'expandedKey' => $case['sk']]);
        $public = $private->getPublicKey();

        $this->assertSame(MLDSA::PARAMETER_SETS[$case['parameterSet']]['signature'], strlen($case['signature']));
        $this->assertTrue($public->verify($case['message'], $case['signature']));
        $this->assertFalse($public->verify($case['message'] . "\0", $case['signature']));
        $this->assertFalse($public->verify(substr($case['message'], 1), $case['signature']));

        // a fresh signature over the same message verifies too (its bytes differ: OpenSSL hedges)
        $signature = $private->sign($case['message']);
        $this->assertSame(strlen($case['signature']), strlen($signature));
        $this->assertTrue($public->verify($case['message'], $signature));
    }

    /**
     * The sigVer verdicts (the three cases without a context all have tampered signatures or messages)
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('sigVerVectors')]
    public function testSigVer(array $case): void
    {
        $public = MLDSA::loadFormat('Raw', ['parameterSet' => $case['parameterSet'], 'publicKey' => $case['pk']]);
        $this->assertInstanceOf(PublicKey::class, $public);

        $this->assertSame($case['testPassed'], $public->verify($case['message'], $case['signature']), (string) $case['reason']);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('sigGenVectors')]
    public function testDeterministicSignature(array $case): void
    {
        self::markTestSkipped("$case[parameterSet] tcId $case[tcId] needs a pure PHP engine: ext/openssl only makes hedged (randomized) signatures, so the deterministic signature bytes can't be reproduced");
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('sigGenVectorsWithContext')]
    public function testSigGenWithContext(array $case): void
    {
        self::markTestSkipped("$case[parameterSet] tcId $case[tcId] needs a pure PHP engine: context strings are not reachable through ext/openssl");
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('sigVerVectorsWithContext')]
    public function testSigVerWithContext(array $case): void
    {
        self::markTestSkipped("$case[parameterSet] tcId $case[tcId] needs a pure PHP engine: context strings are not reachable through ext/openssl");
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('sigVerPreHashVectors')]
    public function testPreHash(array $case): void
    {
        self::markTestSkipped("$case[parameterSet] tcId $case[tcId] ($case[hashAlg]) needs a pure PHP engine: HashML-DSA does not exist in OpenSSL");
    }
}
