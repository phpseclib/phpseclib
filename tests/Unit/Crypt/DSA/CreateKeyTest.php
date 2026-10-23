<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\DSA;

use phpseclib4\Crypt\DSA;
use phpseclib4\Crypt\DSA\Parameters;
use phpseclib4\Crypt\DSA\PrivateKey;
use phpseclib4\Crypt\DSA\PublicKey;
use phpseclib4\Exception\BadConfigurationException;
use phpseclib4\Exception\InvalidArgumentException;
use phpseclib4\Exception\NoKeyLoadedException;
use phpseclib4\Tests\PhpseclibTestCase;

class CreateKeyTest extends PhpseclibTestCase
{
    public function testCreateParameters()
    {
        $dsa = DSA::createParameters();
        $this->assertMatchesRegularExpression('#BEGIN DSA PARAMETERS#', "$dsa");

        $invalidParametersRejected = false;
        try {
            DSA::createParameters(100, 100);
        } catch (InvalidArgumentException) {
            $invalidParametersRejected = true;
        }
        $this->assertTrue($invalidParametersRejected, 'Invalid DSA parameter sizes must be rejected.');

        $dsa = DSA::createParameters(512, 160);
        $this->assertMatchesRegularExpression('#BEGIN DSA PARAMETERS#', "$dsa");

        return $dsa;
    }

    #[\PHPUnit\Framework\Attributes\Depends('testCreateParameters')]
    public function testCreateKey($params): void
    {
        // libsodium doesn't support DSA but it still ought not result in any errors outside of the BadConfigurationException being thrown
        $engines = ['libsodium', 'OpenSSL', 'PHP'];
        foreach ($engines as $engine) {
            try {
                DSA::forceEngine($engine);

                $privatekey = DSA::createKey();
                // @phpstan-ignore method.alreadyNarrowedType (Keep runtime engine-result check.)
                $this->assertInstanceOf(PrivateKey::class, $privatekey);
                // @phpstan-ignore method.alreadyNarrowedType (Keep runtime engine-result check.)
                $this->assertInstanceOf(PublicKey::class, $privatekey->getPublicKey());

                $privatekey = DSA::createKey($params);
                // @phpstan-ignore method.alreadyNarrowedType (Keep runtime engine-result check.)
                $this->assertInstanceOf(PrivateKey::class, $privatekey);
                // @phpstan-ignore method.alreadyNarrowedType (Keep runtime engine-result check.)
                $this->assertInstanceOf(PublicKey::class, $privatekey->getPublicKey());

                $privatekey = DSA::createKey(512, 160);
                // @phpstan-ignore method.alreadyNarrowedType (Keep runtime engine-result check.)
                $this->assertInstanceOf(PrivateKey::class, $privatekey);
                // @phpstan-ignore method.alreadyNarrowedType (Keep runtime engine-result check.)
                $this->assertInstanceOf(PublicKey::class, $privatekey->getPublicKey());
            } catch (BadConfigurationException $e) {
            }
        }
        // reset
        DSA::forceEngine();
    }

    public function testGetFormat(): void
    {
        $key = DSA::createKey();
        try {
            $key->getLoadedFormat();
            $this->fail('Generated keys should not have a loaded format');
        } catch (NoKeyLoadedException) {
        }
        try {
            $key->getPublicKey()->getLoadedFormat();
            $this->fail('The public keys of generated keys should not have a loaded format');
        } catch (NoKeyLoadedException) {
        }
        $this->assertTrue(true);
    }
}
