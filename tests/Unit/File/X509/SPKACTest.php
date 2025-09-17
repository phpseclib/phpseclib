<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\File\X509;

use phpseclib3\Crypt\RSA;
use phpseclib3\File\SPKAC;
use phpseclib3\Tests\PhpseclibTestCase;

class SPKACTest extends PhpseclibTestCase
{
    public function testLoadSPKAC(): void
    {
        $test = 'MIICQDCCASgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChgo9mWzQm3TSwGgpZnIc54' .
                'TZ8gYpfAO/AI0etvyWDqnFfdNCUQsqxTdSi6/rtrJdLGBsszRGrRIc/0JqmjM+jCHGYutLeo4xwgr' .
                'a3HAZrWDypL5IlRWnLmLA4U/qGXCXNSk+9NrJl39X3IDA8o/aOJyr9iMUJMvswcWjVjPom3NhAgmJ' .
                'ZwW0vUEMw9zszExpiRnGSO5XXntQW2qvfzo+J3NzS3BBbKxEmTsfOLHextcXeFQUaBQHXB/WOtweW' .
                'Y/Bd4iZ8ETmhal28g1HWVcTFPD+V+KPRFeARlVEW6JmcJucW2WdJlBGKXXXPEfdHrDS3OgD/eDWfM' .
                'JE4mChZ/icxAgMBAAEWADANBgkqhkiG9w0BAQQFAAOCAQEAUMvIKhlSgEgbC081b/FJwh6mbuVgYN' .
                'ZV37Ts2WjrHoDFlabu9WXU8xzgaXct3sO51vJM5I36rY4UPyc6w3y9dLaamEwKUoWnpHG8mlXs2JG' .
                'GEUOvxh5z9yfk/2ZmdCVBlKnU1LDB+ZDyNyNh5B0YULrJKw9e0jV+ymP7srwUSBcdUfZh1KEKGVIN' .
                'Uv4J3GuL8V63E2unWCHGRPw4EmFVTbWpgMx96XR7p/pMavu6/pVKgYQqWLOmEeOK+dmT/QVon28d5' .
                'dmeL7aWrpP+3x3L0A9cATksracQX676XogdAEXJ59fcr/S5AGw1TFErbyBbfyeAWvzDZIXeMXpb9h' .
                'yNtA==';

        $spkac = SPKAC::load($test)->toArray();

        $this->assertIsArray($spkac);

        $spkac = SPKAC::load('SPKAC=' . $test);

        $this->assertIsArray($spkac->toArray());

        $this->assertTrue(
            $spkac->validateSignature(),
            'Failed asserting that the signature is valid'
        );

        $pubKey = $spkac->getPublicKey();

        $this->assertIsString("$pubKey");
    }

    public function testSaveSPKAC(): void
    {
        $privatekey = RSA::createKey(512)
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->withHash('sha1');

        $spkac = new SPKAC($privatekey->getPublicKey());
        $spkac->setChallenge('...');
        $privatekey->sign($spkac);

        $this->assertIsString("$spkac");

        $spkac = new SPKAC();
        $spkac->setPublicKey($privatekey->getPublicKey());
        $privatekey->sign($spkac);

        $this->assertIsString("$spkac");
    }

    public function testBadSignatureSPKAC(): void
    {
        $test = 'MIICQDCCASgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChgo9mWzQm3TSwGgpZnIc54' .
                'TZ8gYpfAO/AI0etvyWDqnFfdNCUQsqxTdSi6/rtrJdLGBsszRGrRIc/0JqmjM+jCHGYutLeo4xwgr' .
                'a3HAZrWDypL5IlRWnLmLA4U/qGXCXNSk+9NrJl39X3IDA8o/aOJyr9iMUJMvswcWjVjPom3NhAgmJ' .
                'ZwW0vUEMw9zszExpiRnGSO5XXntQW2qvfzo+J3NzS3BBbKxEmTsfOLHextcXeFQUaBQHXB/WOtweW' .
                'Y/Bd4iZ8ETmhal28g1HWVcTFPD+V+KPRFeARlVEW6JmcJucW2WdJlBGKXXXPEfdHrDS3OgD/eDWfM' .
                'JE4mChZ/icxAgMBAAEWADANBgkqhkiG9w0BAQQFAAOCAQEAUMvIKhlSgEgbC081b/FJwh6mbuVgYN' .
                'ZV37Ts2WjrHoDFlabu9WXU8xzgaXct3sO51vJM5I36rY4UPyc6w3y9dLaamEwKUoWnpHG8mlXs2JG' .
                'GEUOvxh5z9yfk/2ZmdCVBlKnU1LDB+ZDyNyNh5B0YULrJKw9e0jV+ymP7srwUSBcdUfZh1KEKGVIN' .
                'Uv4J3GuL8V63E2unWCHGRPw4EmFVTbWpgMx96XR7p/pMavu6/pVKgYQqWLOmEeOK+dmT/QVon28d5' .
                'dmeL7aWrpP+3x3L0A9cATksracQX676XogdAEXJ59fcr/S5AGw1TFErbyBbfyeAWvzDZIXeMXpb9h' .
                'yNtA==';

        $spkac = SPKAC::load($test);

        $this->assertTrue(
            $spkac->validateSignature(),
            'Failed asserting that the signature is valid'
        );

        $spkac['publicKeyAndChallenge']['challenge'] = 'zzzz';

        $this->assertFalse(
            $spkac->validateSignature(),
            'Failed asserting that the signature is invalid'
        );
    }
}
