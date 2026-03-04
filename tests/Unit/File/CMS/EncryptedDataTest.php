<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\File\CMS;

use phpseclib4\File\CMS;
use phpseclib4\File\ASN1\Types\OID;
use phpseclib4\Tests\PhpseclibTestCase;

class EncryptedDataTest extends PhpseclibTestCase
{
    public function testDecrypt(): void
    {
        // generated thusly:
        // openssl cms -EncryptedData_encrypt -in plaintext.txt -out encrypted.p7m -outform PEM -aes256 -secretkey 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
        $cms = CMS::load('-----BEGIN CMS-----
MFAGCSqGSIb3DQEHBqBDMEECAQAwPAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQ
lHt+YbD7A18NJVeJgx0R9IAQKnjC5UnRa0hP1rdkZs+Y5Q==
-----END CMS-----');
        $this->assertInstanceOf(OID::class, $cms['contentType']);
        $this->assertNotContains('recipientInfos', $cms['content']);
        $decrypted = $cms->withKey(hex2bin('00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'))->decrypt();
        $this->assertEquals("hello, world!\r\n", $decrypted);
    }

    public function testEncrypt(): void
    {
        $plaintext = 'asdfasdfsadf';
        $key = str_repeat('x', 16);
        $cms = new CMS\EncryptedData($plaintext, key: $key);
        $decrypted = CMS::load("$cms")->withKey($key)->decrypt();
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testKeyLength(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MFAGCSqGSIb3DQEHBqBDMEECAQAwPAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQ
lHt+YbD7A18NJVeJgx0R9IAQKnjC5UnRa0hP1rdkZs+Y5Q==
-----END CMS-----');
        $this->assertEquals(32, $cms->getKeyLengthInBytes());
    }
}
