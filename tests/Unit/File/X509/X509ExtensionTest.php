<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\File\X509;

use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\RSA;
use phpseclib4\File\ASN1;
use phpseclib4\File\X509;
use phpseclib4\Tests\PhpseclibTestCase;

class X509ExtensionTest extends PhpseclibTestCase
{
    public function testCustomExtension(): void
    {
        $customExtensionData = [
            'toggle' => true,
            'num' => 3,
            'name' => 'Johnny',
            'list' => ['foo', 'bar'],
        ];
        $customExtensionName = 'cust';
        $customExtensionNumber = '2.16.840.1.101.3.4.2.99';
        $customExtensionMapping = [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'toggle' => ['type' => ASN1::TYPE_BOOLEAN],
                'num' => ['type' => ASN1::TYPE_INTEGER],
                'name' => ['type' => ASN1::TYPE_OCTET_STRING],
                'list' => [
                    'type' => ASN1::TYPE_SEQUENCE,
                    'min' => 0,
                    'max' => -1,
                    'children' => ['type' => ASN1::TYPE_OCTET_STRING],
                ],
            ],
        ];

        ASN1::loadOIDs([
            $customExtensionName => $customExtensionNumber,
        ]);

        X509::registerExtension($customExtensionName, $customExtensionMapping);

        $privateKey = RSA::createKey();

        $publicKey = $privateKey->getPublicKey();

        $certificate = new X509($publicKey);
        $certificate->addDNProp('id-at-organizationName', 'phpseclib CA cert');
        $certificate->makeCA();
        $certificate->setExtension($customExtensionName, $customExtensionData, false);
        $privateKey->sign($certificate);

        $decodedData = X509::load("$certificate");
        $customExtensionDecodedData = null;

        foreach ($decodedData['tbsCertificate']['extensions'] as $extension) {
            if ("$extension[extnId]" === $customExtensionName) {
                $customExtensionDecodedData = $extension['extnValue'];

                break;
            }
        }

        $this->assertTrue($customExtensionDecodedData['toggle']->value);
        $this->assertInstanceOf('phpseclib4\Math\BigInteger', $customExtensionDecodedData['num']);
        $this->assertSame('3', (string) $customExtensionDecodedData['num']);
        $this->assertSame('Johnny', (string) $customExtensionDecodedData['name']);
        $this->assertSame(['foo', 'bar'], array_map(fn($x) => "$x", $customExtensionDecodedData['list']->toArray()));
        $this->assertSame($customExtensionMapping, X509::getRegisteredExtension($customExtensionName));
    }

    public function testCustomExtensionRegisterConflict(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Extension bar has already been defined with a different mapping.');

        X509::registerExtension('bar', ['type' => ASN1::TYPE_OCTET_STRING]);
        X509::registerExtension('bar', ['type' => ASN1::TYPE_ANY]);
    }

    public function testExtensionsAreInitializedIfMissing(): void
    {
        $issuerKey = EC::createKey('ed25519');
        $subjectKey = EC::createKey('ed25519')->getPublicKey();

        $cert = new X509($subjectKey);
        $cert->setSubjectDN(['commonName' => 'subject']);
        $cert->setIssuerDN(['commonName' => 'issuer']);
        $cert->setExtension('id-ce-keyUsage', ['digitalSignature']);
        $issuerKey->sign($cert);

        $ext =  X509::load("$cert")['tbsCertificate']['extensions']->toArray()[0];

        $this->assertEquals('id-ce-keyUsage', $ext['extnId']);
        $this->assertEquals(true, $ext['critical']->value);
        $this->assertEquals(['digitalSignature'], $ext['extnValue']->toArray());
    }
}
