<?php

/**
 * Real OpenSSL coverage for the base class's OFB8 and emulated CTR paths.
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\AES;

use phpseclib4\Crypt\AES;
use phpseclib4\Tests\PhpseclibTestCase;

class OpenSSLModeTest extends PhpseclibTestCase
{
    public function testEmulatedCTRKnownAnswer(): void
    {
        // NIST SP 800-38A, F.5.1: first two AES-128 CTR blocks.
        $cipher = new OpenSSLModeCipher('ctr');
        $cipher->setPreferredEngine('OpenSSL');
        $cipher->setKey(hex2bin('2b7e151628aed2a6abf7158809cf4f3c'));
        $cipher->setIV(hex2bin('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'));
        $cipher->enableContinuousBuffer();
        if ($cipher->getEngine() !== 'OpenSSL') {
            self::markTestSkipped('OpenSSL AES ECB is unavailable');
        }
        $this->assertTrue(self::getVar($cipher, 'openssl_emulate_ctr'));
        $plaintext = hex2bin('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51');
        $expected = hex2bin('874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff');
        $this->assertSame($expected, $cipher->encrypt(substr($plaintext, 0, 16)) . $cipher->encrypt(substr($plaintext, 16)));
        $this->assertSame($plaintext, $cipher->decrypt(substr($expected, 0, 16)) . $cipher->decrypt(substr($expected, 16)));
    }

    public function testOFB8ModeTranslationExtension(): void
    {
        $cipher = new OpenSSLModeCipher('ofb8');
        $reference = new AES('ofb8');
        $reference->setPreferredEngine('PHP');
        foreach ([$cipher, $reference] as $instance) {
            $instance->setKey(str_repeat('K', 16));
            $instance->setIV(str_repeat('I', 16));
            $instance->enableContinuousBuffer();
        }
        $cipher->setPreferredEngine('OpenSSL');
        if ($cipher->getEngine() !== 'OpenSSL') {
            self::markTestSkipped('OpenSSL AES ECB is unavailable');
        }

        // The existing OFB8 implementation passes its IV to ECB. PHP ignores it
        // with this warning; account for that known behavior, not arbitrary warnings.
        $warnings = 0;
        set_error_handler(static function (int $severity, string $message) use (&$warnings): bool {
            if ($severity === E_WARNING && str_contains($message, 'IV passed is 16 bytes long which is longer than the 0 expected by selected cipher')) {
                ++$warnings;
                return true;
            }
            return false;
        });
        try {
            foreach (['a', 'bc', 'defghijklmnopq'] as $plaintext) {
                $encrypted = $cipher->encrypt($plaintext);
                $this->assertSame($reference->encrypt($plaintext), $encrypted);
                $this->assertSame($plaintext, $cipher->decrypt($encrypted));
            }
        } finally {
            restore_error_handler();
        }
        $this->assertGreaterThan(0, $warnings);
    }
}
