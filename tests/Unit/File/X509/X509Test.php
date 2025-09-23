<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\File\X509;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\EC;
use phpseclib3\Exception\RuntimeException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Element;
use phpseclib3\File\ASN1\MalformedData;
use phpseclib3\File\ASN1\Types\PrintableString;
use phpseclib3\File\ASN1\Types\UTF8String;
use phpseclib3\File\X509;
use phpseclib3\Tests\PhpseclibTestCase;

class X509Test extends PhpseclibTestCase
{
    public function testExtensionMapping(): void
    {
        $test = '-----BEGIN CERTIFICATE-----
MIIG1jCCBL6gAwIBAgITUAAAAA0qg8bE6DhrLAAAAAAADTANBgkqhkiG9w0BAQsF
ADAiMSAwHgYDVQQDExcuU2VjdXJlIEVudGVycHJpc2UgQ0EgMTAeFw0xNTAyMjMx
NTE1MDdaFw0xNjAyMjMxNTE1MDdaMD8xFjAUBgoJkiaJk/IsZAEZFgZzZWN1cmUx
DjAMBgNVBAMTBVVzZXJzMRUwEwYDVQQDEwxtZXRhY2xhc3NpbmcwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMdG1CzR/gTalbLN9J+2cvMGeD7wsR7S78
HU5hdwE+kECROjRAcjFBOR57ezSDrkmhkTzo28tj0oAHjOh8N9vuXtASfZSCXugx
H+ImJ+E7PA4aXBp+0H2hohW9sXNNCFiVNmJLX66O4bxIeKtVRq/+eSNijV4OOEkC
zMyTHAUbOFP0t6KoJtM1syNoQ1+fKdfcjz5XtiEzSVcp2zf0MwNFSeZSgGQ0jh8A
Kd6YVKA8ZnrqOWZxKETT+bBNTjIT0ggjQfzcE4zW2RzrN7zWabUowoU92+DAp4s3
sAEywX9ISSge62DEzTnZZSf9bpoScAfT8raRFA3BkoJ/s4c4CgfPAgMBAAGjggLm
MIIC4jAdBgNVHQ4EFgQULlIyJL9+ZwAI/SkVdsJMxFOVp+EwHwYDVR0jBBgwFoAU
5nEIMEUT5mMd1WepmviwgK7dIzwwggEKBgNVHR8EggEBMIH+MIH7oIH4oIH1hoG5
bGRhcDovLy9DTj0uU2VjdXJlJTIwRW50ZXJwcmlzZSUyMENBJTIwMSxDTj1hdXRo
LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
Tj1Db25maWd1cmF0aW9uLERDPXNlY3VyZT9jZXJ0aWZpY2F0ZVJldm9jYXRpb25M
aXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGN2h0dHA6
Ly9jcmwuc2VjdXJlb2JzY3VyZS5jb20vP2FjdGlvbj1jcmwmY2E9ZW50ZXJwcmlz
ZTEwgccGCCsGAQUFBwEBBIG6MIG3MIG0BggrBgEFBQcwAoaBp2xkYXA6Ly8vQ049
LlNlY3VyZSUyMEVudGVycHJpc2UlMjBDQSUyMDEsQ049QUlBLENOPVB1YmxpYyUy
MEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9
c2VjdXJlP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0
aW9uQXV0aG9yaXR5MBcGCSsGAQQBgjcUAgQKHggAVQBzAGUAcjAOBgNVHQ8BAf8E
BAMCBaAwKQYDVR0lBCIwIAYKKwYBBAGCNwoDBAYIKwYBBQUHAwQGCCsGAQUFBwMC
MC4GA1UdEQQnMCWgIwYKKwYBBAGCNxQCA6AVDBNtZXRhY2xhc3NpbmdAc2VjdXJl
MEQGCSqGSIb3DQEJDwQ3MDUwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIA
gDAHBgUrDgMCBzAKBggqhkiG9w0DBzANBgkqhkiG9w0BAQsFAAOCAgEAKNmjYh+h
cObJEM0CWgz50jOYKZ4M5iIxoAWgrYY9Pv+0O9aPjvPLzjd5bY322L8lxh5wy5my
DKmip+irzjdVdxzQfoyy+ceODmCbX9L6MfEDn0RBzdwjLe1/eOxE1na0sZztrVCc
yt5nI91NNGZJUcVqVQsIA/25FWlkvo/FTfuqTuXdQiEVM5MCKJI915anmTdugy+G
0CmBJALIxtyz5P7sZhaHZFNdpKnx82QsauErqjP9H0RXc6VXX5qt+tEDvYfSlFcc
0lv3aQnV/eIdfm7APJkQ3lmNWWQwdkVf7adXJ7KAAPHSt1yvSbVxThJR/jmIkyeQ
XW/TOP5m7JI/GrmvdlzI1AgwJ+zO8fOmCDuif99pDb1CvkzQ65RZ8p5J1ZV6hzlb
VvOhn4LDnT1jnTcEqigmx1gxM/5ifvMorXn/ItMjKPlb72vHpeF7OeKE8GHsvZAm
osHcKyJXbTIcXchmpZX1efbmCMJBqHgJ/qBTBMl9BX0+YqbTZyabRJSs9ezbTRn0
oRYl21Q8EnvS71CemxEUkSsKJmfJKkQNCsOjc8AbX/V/X9R7LJkH3UEx6K2zQQKK
k6m17mi63YW/+iPCGOWZ2qXmY5HPEyyF2L4L4IDryFJ+8xLyw3pH9/yp5aHZDtp6
833K6qyjgHJT+fUzSEYpiwF5rSBJIGClOCY=
-----END CERTIFICATE-----';

        $cert = X509::load($test);

        $this->assertIsArray($cert->toArray()['tbsCertificate']['extensions'][3]['extnValue']);
        $this->assertIsArray($cert->getExtension('id-pe-authorityInfoAccess')['extnValue']->toArray());

        $this->assertEquals(1, $cert['tbsCertificate']->depth);
        $this->assertEquals(2, $cert['tbsCertificate']['extensions']->depth);
        $this->assertEquals(3, $cert['tbsCertificate']['extensions'][3]->depth);
        $this->assertEquals(4, $cert['tbsCertificate']['extensions'][3]['extnValue']->depth);

        $this->assertEquals(
            $cert->getEncoded(),
            $cert['tbsCertificate']->parent->getEncoded()
        );
        $this->assertEquals(
            $cert['tbsCertificate']->getEncoded(),
            $cert['tbsCertificate']['extensions']->parent->getEncoded()
        );
        $this->assertEquals(
            $cert['tbsCertificate']['extensions']->getEncoded(),
            $cert['tbsCertificate']['extensions'][3]->parent->getEncoded()
        );
        $this->assertEquals(
            $cert['tbsCertificate']['extensions'][3]->getEncoded(),
            $cert['tbsCertificate']['extensions'][3]['extnValue']->parent->getEncoded()
        );
    }

    public function testLoadUnsupportedExtension(): void
    {
        $test = '-----BEGIN CERTIFICATE-----
MIIG1jCCBL6gAwIBAgITUAAAAA0qg8bE6DhrLAAAAAAADTANBgkqhkiG9w0BAQsF
ADAiMSAwHgYDVQQDExcuU2VjdXJlIEVudGVycHJpc2UgQ0EgMTAeFw0xNTAyMjMx
NTE1MDdaFw0xNjAyMjMxNTE1MDdaMD8xFjAUBgoJkiaJk/IsZAEZFgZzZWN1cmUx
DjAMBgNVBAMTBVVzZXJzMRUwEwYDVQQDEwxtZXRhY2xhc3NpbmcwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMdG1CzR/gTalbLN9J+2cvMGeD7wsR7S78
HU5hdwE+kECROjRAcjFBOR57ezSDrkmhkTzo28tj0oAHjOh8N9vuXtASfZSCXugx
H+ImJ+E7PA4aXBp+0H2hohW9sXNNCFiVNmJLX66O4bxIeKtVRq/+eSNijV4OOEkC
zMyTHAUbOFP0t6KoJtM1syNoQ1+fKdfcjz5XtiEzSVcp2zf0MwNFSeZSgGQ0jh8A
Kd6YVKA8ZnrqOWZxKETT+bBNTjIT0ggjQfzcE4zW2RzrN7zWabUowoU92+DAp4s3
sAEywX9ISSge62DEzTnZZSf9bpoScAfT8raRFA3BkoJ/s4c4CgfPAgMBAAGjggLm
MIIC4jAdBgNVHQ4EFgQULlIyJL9+ZwAI/SkVdsJMxFOVp+EwHwYDVR0jBBgwFoAU
5nEIMEUT5mMd1WepmviwgK7dIzwwggEKBgNVHR8EggEBMIH+MIH7oIH4oIH1hoG5
bGRhcDovLy9DTj0uU2VjdXJlJTIwRW50ZXJwcmlzZSUyMENBJTIwMSxDTj1hdXRo
LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
Tj1Db25maWd1cmF0aW9uLERDPXNlY3VyZT9jZXJ0aWZpY2F0ZVJldm9jYXRpb25M
aXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGN2h0dHA6
Ly9jcmwuc2VjdXJlb2JzY3VyZS5jb20vP2FjdGlvbj1jcmwmY2E9ZW50ZXJwcmlz
ZTEwgccGCCsGAQUFBwEBBIG6MIG3MIG0BggrBgEFBQcwAoaBp2xkYXA6Ly8vQ049
LlNlY3VyZSUyMEVudGVycHJpc2UlMjBDQSUyMDEsQ049QUlBLENOPVB1YmxpYyUy
MEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9
c2VjdXJlP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0
aW9uQXV0aG9yaXR5MBcGCSsGAQQBgjcUAgQKHggAVQBzAGUAcjAOBgNVHQ8BAf8E
BAMCBaAwKQYDVR0lBCIwIAYKKwYBBAGCNwoDBAYIKwYBBQUHAwQGCCsGAQUFBwMC
MC4GA1UdEQQnMCWgIwYKKwYBBAGCNxQCA6AVDBNtZXRhY2xhc3NpbmdAc2VjdXJl
MEQGCSqGSIb3DQEJDwQ3MDUwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIA
gDAHBgUrDgMCBzAKBggqhkiG9w0DBzANBgkqhkiG9w0BAQsFAAOCAgEAKNmjYh+h
cObJEM0CWgz50jOYKZ4M5iIxoAWgrYY9Pv+0O9aPjvPLzjd5bY322L8lxh5wy5my
DKmip+irzjdVdxzQfoyy+ceODmCbX9L6MfEDn0RBzdwjLe1/eOxE1na0sZztrVCc
yt5nI91NNGZJUcVqVQsIA/25FWlkvo/FTfuqTuXdQiEVM5MCKJI915anmTdugy+G
0CmBJALIxtyz5P7sZhaHZFNdpKnx82QsauErqjP9H0RXc6VXX5qt+tEDvYfSlFcc
0lv3aQnV/eIdfm7APJkQ3lmNWWQwdkVf7adXJ7KAAPHSt1yvSbVxThJR/jmIkyeQ
XW/TOP5m7JI/GrmvdlzI1AgwJ+zO8fOmCDuif99pDb1CvkzQ65RZ8p5J1ZV6hzlb
VvOhn4LDnT1jnTcEqigmx1gxM/5ifvMorXn/ItMjKPlb72vHpeF7OeKE8GHsvZAm
osHcKyJXbTIcXchmpZX1efbmCMJBqHgJ/qBTBMl9BX0+YqbTZyabRJSs9ezbTRn0
oRYl21Q8EnvS71CemxEUkSsKJmfJKkQNCsOjc8AbX/V/X9R7LJkH3UEx6K2zQQKK
k6m17mi63YW/+iPCGOWZ2qXmY5HPEyyF2L4L4IDryFJ+8xLyw3pH9/yp5aHZDtp6
833K6qyjgHJT+fUzSEYpiwF5rSBJIGClOCY=
-----END CERTIFICATE-----';

        $cert = X509::load($test);

        $expected = base64_decode('MDUwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAHBgUrDgMCBzAKBggqhkiG9w0DBw==');
        $this->assertEquals($expected, $cert->toArray()['tbsCertificate']['extensions'][8]['extnValue']->value);
        $this->assertEquals($expected, $cert['tbsCertificate']['extensions'][8]['extnValue']->value);
        $this->assertEquals($expected, $cert->getExtension('pkcs-9-at-smimeCapabilities')['extnValue']->value);
    }

    public function testSaveUnsupportedExtension(): void
    {
        $x509 = X509::load('-----BEGIN CERTIFICATE-----
MIIDITCCAoqgAwIBAgIQT52W2WawmStUwpV8tBV9TTANBgkqhkiG9w0BAQUFADBM
MQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkg
THRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0xMTEwMjYwMDAwMDBaFw0x
MzA5MzAyMzU5NTlaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
MRYwFAYDVQQHFA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKFApHb29nbGUgSW5jMRcw
FQYDVQQDFA53d3cuZ29vZ2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEA3rcmQ6aZhc04pxUJuc8PycNVjIjujI0oJyRLKl6g2Bb6YRhLz21ggNM1QDJy
wI8S2OVOj7my9tkVXlqGMaO6hqpryNlxjMzNJxMenUJdOPanrO/6YvMYgdQkRn8B
d3zGKokUmbuYOR2oGfs5AER9G5RqeC1prcB6LPrQ2iASmNMCAwEAAaOB5zCB5DAM
BgNVHRMBAf8EAjAAMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwudGhhd3Rl
LmNvbS9UaGF3dGVTR0NDQS5jcmwwKAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUF
BwMCBglghkgBhvhCBAEwcgYIKwYBBQUHAQEEZjBkMCIGCCsGAQUFBzABhhZodHRw
Oi8vb2NzcC50aGF3dGUuY29tMD4GCCsGAQUFBzAChjJodHRwOi8vd3d3LnRoYXd0
ZS5jb20vcmVwb3NpdG9yeS9UaGF3dGVfU0dDX0NBLmNydDANBgkqhkiG9w0BAQUF
AAOBgQAhrNWuyjSJWsKrUtKyNGadeqvu5nzVfsJcKLt0AMkQH0IT/GmKHiSgAgDp
ulvKGQSy068Bsn5fFNum21K5mvMSf3yinDtvmX3qUA12IxL/92ZzKbeVCq3Yi7Le
IOkKcGQRCMha8X2e7GmlpdWC1ycenlbN0nbVeSv3JUMcafC4+Q==
-----END CERTIFICATE-----');

        $oid = '1.2.3.4';
        $value = ASN1::encodeOID($oid);
        $ext = chr(ASN1::TYPE_OBJECT_IDENTIFIER) . ASN1::encodeLength(strlen($value)) . $value;
        $value = 'zzzzzzzzz';
        $ext .= chr(ASN1::TYPE_OCTET_STRING) . ASN1::encodeLength(strlen($value)) . $value;
        $ext = chr(ASN1::TYPE_SEQUENCE | 0x20) . ASN1::encodeLength(strlen($ext)) . $ext;

        $this->assertCount(4, $x509['tbsCertificate']['extensions']);

        $x509['tbsCertificate']['extensions'][4] = new Element($ext);

        $this->assertCount(5, $x509['tbsCertificate']['extensions']);
        $x509 = X509::load("$x509");
        $this->assertCount(5, $x509['tbsCertificate']['extensions']);

        // the order for this matters. if you do unset($x509['tbsCertificate']['extensions'][0]) first
        // then what had been $x509['tbsCertificate']['extensions'][4] will all of a sudden be
        // $x509['tbsCertificate']['extensions'][3]
        unset($x509['tbsCertificate']['extensions'][4]);
        unset($x509['tbsCertificate']['extensions'][0]);

        $this->assertCount(3, $x509['tbsCertificate']['extensions']);
        $x509 = X509::load("$x509");
        $this->assertCount(3, $x509['tbsCertificate']['extensions']);

        // the following won't work because phpseclib doesn't save unknown / unsupported extensions
        // the chief reason for this is that it doesn't know how to encode extensions it doesn't know
        // about. like if you pass a string is that supposed to be a UTF8String or an OctetString?
        // phpseclib don't know! i suppose an exception could be made if $value is an ASN1\Element
        // but no such exception currently exists
        //$x509->setExtension($oid, $value, true);
        //$this->assertCount(4, $x509['tbsCertificate']['extensions']);
        //$x509 = X509::load("$x509");
        //$this->assertCount(4, $x509['tbsCertificate']['extensions']);
    }

    /**
     * @group github705
     */
    public function testSaveNullRSAParam(): void
    {
        $privKey = PublicKeyLoader::load('-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDMswfEpAgnUDWA74zZw5XcPsWh1ly1Vk99tsqwoFDkLF7jvXy1
dDLHYfuquvfxCgcp8k/4fQhx4ubR8bbGgEq9B05YRnViK0R0iBB5Ui4IaxWYYhKE
8xqAEH2fL+/7nsqqNFKkEN9KeFwc7WbMY49U2adlMrpBdRjk1DqIEW3QTwIDAQAB
AoGBAJ+83cT/1DUJjJcPWLTeweVbPtJp+3Ku5d1OdaGbmURVs764scbP5Ihe2AuF
V9LLZoe/RdS9jYeB72nJ3D3PA4JVYYgqMOnJ8nlUMNQ+p0yGl5TqQk6EKLI8MbX5
kQEazNqFXsiWVQXubAd5wjtb6g0n0KD3zoT/pWLES7dtUFexAkEA89h5+vbIIl2P
H/NnkPie2NWYDZ1YiMGHFYxPDwsd9KCZMSbrLwAhPg9bPgqIeVNfpwxrzeksS6D9
P98tJt335QJBANbnCe+LhDSrkpHMy9aOG2IdbLGG63MSRUCPz8v2gKPq3kYXDxq6
Y1iqF8N5g0k5iirHD2qlWV5Q+nuGvFTafCMCQQC1wQiC0IkyXEw/Q31RqI82Dlcs
5rhEDwQyQof3LZEhcsdcxKaOPOmKSYX4A3/f9w4YBIEiVQfoQ1Ig1qfgDZklAkAT
TQDJcOBY0qgBTEFqbazr7PScJR/0X8m0eLYS/XqkPi3kYaHLpr3RcsVbmwg9hVtx
aBtsWpliLSex/HHhtRW9AkBGcq67zKmEpJ9kXcYLEjJii3flFS+Ct/rNm+Hhm1l7
4vca9v/F2hGVJuHIMJ8mguwYlNYzh2NqoIDJTtgOkBmt
-----END RSA PRIVATE KEY-----');
        $privKey = $privKey
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->withHash('sha1');

        $pubKey = $privKey->getPublicKey();

        $cert = new X509();
        $cert->addDNProp('id-at-organizationName', 'phpseclib demo cert');
        $cert->setPublicKey($pubKey);
        $cert->setEndDate('lifetime');
        $privKey->sign($cert);

        $this->assertArrayHasKey('parameters', $cert['signatureAlgorithm']->toArray());
        $this->assertArrayHasKey('parameters', $cert['tbsCertificate']['signature']->toArray());
    }

    public function testGetOID(): void
    {
        $this->assertEquals(ASN1::getOIDFromName('1.2.840.113549.1.1.5'), '1.2.840.113549.1.1.5');
        $this->assertEquals(ASN1::getOIDFromName('sha1WithRSAEncryption'), '1.2.840.113549.1.1.5');
        $this->assertEquals(ASN1::getOIDFromName('zzz'), 'zzz');
    }

    public function testIPAddressSubjectAltNamesDecoding(): void
    {
        $test = '-----BEGIN CERTIFICATE-----
MIIEcTCCAlmgAwIBAgIBDjANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBQuU2Vj
dXJlIElzc3VpbmcgQ0EgMTAeFw0xNjAxMjUyMzIwMjZaFw0yMTAxMjYyMzIwMjZa
MBoxGDAWBgNVBAMMDzIwNC4xNTIuMjAwLjI1MDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAM9lMPiYQ26L5qXR1rlUXM0Z3DeRhDsJ/9NadLFJnvxKCV5L
M9rlrThpK6V5VbgPgEwKVLXGtJoGSEUkLd4roJ25ZTH08GcYszWyp8nLPQRovYnN
+aeE1aefnHcpt524f0Es9NFXh0uwRWV3ZCWSwN+mo9Qo6507KZq+q34if7/q9+De
O5RJumVQWc9OCjCt6pQBnBua9oCAca+SIHftOdgWXqVw+Xvl6/dLeF70jJD43P00
+bdAnGDgBdgO+p+K+XrOCaCWMcCsRX5xiK4hUG54UM5ayBST+McyfjsKxpO2djPg
FlSL0RLg+Nj8WehANUUuaNU874Pp3FV5GTI0ZbUCAwEAAaOBvDCBuTAMBgNVHRMB
Af8EAjAAMAsGA1UdDwQEAwIF4DATBgNVHSUEDDAKBggrBgEFBQcDATAhBgNVHREE
GjAYhwTMmMj6hxAgAQRw8wkACQAAAAAAAAADMEMGA1UdHwQ8MDowOKA2oDSGMmh0
dHA6Ly9jcmwuc2VjdXJlb2JzY3VyZS5jb20vP2FjdGlvbj1jcmwmY2E9aXNzdWUx
MB8GA1UdIwQYMBaAFOJWVCX4poZSBzemgihf9dAhFNHJMA0GCSqGSIb3DQEBCwUA
A4ICAQAce9whx4InRtzk1to6oeRxTCbeNDjNFuTkotphSws4hDoaz3nyFLSYyMT4
aKFnNP9AmMS5nEXphtP4HP9wAluTcAFMuip0rDJjiRA/khIE27KurO6cg1faFWHl
6lh6xnEf9UFZZzTLsXt2miBiMb8olgPrBuVFWjPZ/ConesJRZRFqMd5mfntXC+2V
zRcXdtwp9h/Am/WuvjsG/gBAPdeRNKffCokIcgfvffd2oklSDD0T9baG2MTgaxnX
oG6e5saWjoN8bLWuCJpvjA7aErXQwXUyXx1nrTWQ1TCR2N+M62X7e07jZLKSAECP
v6SqZ9/LDmCacVQbfg4wDC/gbpjDSKaD5fkusH6leXleWQ7X8Z03LsKvVq43a71z
jO61kkiFAh3CegWsY+TSYjZxDq58xGMiE7y/fK+SHQXDLyY7HU4eky2l3DSy8bXQ
p64vTJ/OmAcXVNUASfBCNw0kpxuFjlxers/+6zheowB1RIKo0xvSRC4cEDRl/jFA
b7WUT/MIe6B1r0v1gxHnFG2bFI/MhTT9V+tICOLo7+69z4jf/OFkzjYvqq2QWPgc
sE3f2TNnmKFRJx67bEMoaaWLIR94Yuq/TWB6dTiWwk9meZkGG3OjQg/YbO6vl/Am
NDEuGt30Vl2de7G1glnhaceB6Q9KfH7p2gAwNP9JMTtx3PtEcA==
-----END CERTIFICATE-----';

        $cert = X509::load($test);
        $this->assertEquals('204.152.200.250', $cert['tbsCertificate']['extensions'][3]['extnValue'][0]['iPAddress']);
        $this->assertEquals('2001:470:f309:9::3', $cert['tbsCertificate']['extensions'][3]['extnValue'][1]['iPAddress']);

        $this->assertEquals('204.152.200.250', (string) $cert->getExtension('id-ce-subjectAltName')['extnValue'][0]);
        $this->assertEquals('2001:470:f309:9::3', (string) $cert->getExtension('id-ce-subjectAltName')['extnValue'][1]);
    }

    public function testPostalAddress(): void
    {
        $x509 = X509::load('-----BEGIN CERTIFICATE-----
MIIFzzCCBLegAwIBAgIDAfdlMA0GCSqGSIb3DQEBBQUAMHMxCzAJBgNVBAYTAlBM
MSgwJgYDVQQKDB9LcmFqb3dhIEl6YmEgUm96bGljemVuaW93YSBTLkEuMSQwIgYD
VQQDDBtDT1BFIFNaQUZJUiAtIEt3YWxpZmlrb3dhbnkxFDASBgNVBAUTC05yIHdw
aXN1OiA2MB4XDTExMTEwOTA2MDAwMFoXDTEzMTEwOTA2MDAwMFowgdkxCzAJBgNV
BAYTAlBMMRwwGgYDVQQKDBNVcnrEhWQgTWlhc3RhIEdkeW5pMRswGQYDVQQFExJQ
RVNFTDogNjEwNjA2MDMxMTgxGTAXBgNVBAMMEEplcnp5IFByemV3b3Jza2kxTzBN
BgNVBBAwRgwiQWwuIE1hcnN6YcWCa2EgUGnFgnN1ZHNraWVnbyA1Mi81NAwNODEt
MzgyIEdkeW5pYQwGUG9sc2thDAlwb21vcnNraWUxDjAMBgNVBCoMBUplcnp5MRMw
EQYDVQQEDApQcnpld29yc2tpMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCM
m5vjGqHPthJCMqKpqssSISRos0PYDTcEQzyyurfX67EJWKtZj6HNwuDMEGJ02iBN
ZfjUl7r8dIi28bSKhNlsfycXZKYRcIjp0+r5RqtR2auo9GQ6veKb61DEAGIqaR+u
LLcJVTHCu0w9oXLGbRlGth5eNoj03CxXVAH2IfhbNwIDAQABo4IChzCCAoMwDAYD
VR0TAQH/BAIwADCCAUgGA1UdIAEB/wSCATwwggE4MIIBNAYJKoRoAYb3IwEBMIIB
JTCB3QYIKwYBBQUHAgIwgdAMgc1EZWtsYXJhY2phIHRhIGplc3Qgb8Wbd2lhZGN6
ZW5pZW0gd3lkYXdjeSwgxbxlIHRlbiBjZXJ0eWZpa2F0IHpvc3RhxYIgd3lkYW55
IGpha28gY2VydHlmaWthdCBrd2FsaWZpa293YW55IHpnb2RuaWUgeiB3eW1hZ2Fu
aWFtaSB1c3Rhd3kgbyBwb2RwaXNpZSBlbGVrdHJvbmljem55bSBvcmF6IHRvd2Fy
enlzesSFY3ltaSBqZWogcm96cG9yesSFZHplbmlhbWkuMEMGCCsGAQUFBwIBFjdo
dHRwOi8vd3d3Lmtpci5jb20ucGwvY2VydHlmaWthY2phX2tsdWN6eS9wb2xpdHlr
YS5odG1sMAkGA1UdCQQCMAAwIQYDVR0RBBowGIEWai5wcnpld29yc2tpQGdkeW5p
YS5wbDAOBgNVHQ8BAf8EBAMCBkAwgZ4GA1UdIwSBljCBk4AU3TGldJXipN4oGS3Z
YmnBDMFs8gKhd6R1MHMxCzAJBgNVBAYTAlBMMSgwJgYDVQQKDB9LcmFqb3dhIEl6
YmEgUm96bGljemVuaW93YSBTLkEuMSQwIgYDVQQDDBtDT1BFIFNaQUZJUiAtIEt3
YWxpZmlrb3dhbnkxFDASBgNVBAUTC05yIHdwaXN1OiA2ggJb9jBIBgNVHR8EQTA/
MD2gO6A5hjdodHRwOi8vd3d3Lmtpci5jb20ucGwvY2VydHlmaWthY2phX2tsdWN6
eS9DUkxfT1pLMzIuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQBYPIqnAreyeql7/opJ
jcar/qWZy9ruhB2q0lZFsJOhwgMnbQXzp/4vv93YJqcHGAXdHP6EO8FQX47mjo2Z
KQmi+cIHJHLONdX/3Im+M17V0iNAh7Z1lOSfTRT+iiwe/F8phcEaD5q2RmvYusR7
zXZq/cLL0If0hXoPZ/EHQxjN8pxzxiUx6bJAgturnIMEfRNesxwghdr1dkUjOhGL
f3kHVzgM6j3VAM7oFmMUb5y5s96Bzl10DodWitjOEH0vvnIcsppSxH1C1dCAi0o9
f/1y2XuLNhBNHMAyTqpYPX8Yvav1c+Z50OMaSXHAnTa20zv8UtiHbaAhwlifCelU
Mj93
-----END CERTIFICATE-----');
        $expected = [
            "Al. Marsza\xC5\x82ka Pi\xC5\x82sudskiego 52/54",
            '81-382 Gdynia',
            'Polska',
            'pomorskie',
        ];
        $actual = $x509->getSubjectDNProps('id-at-postalAddress')[0];
        $this->assertEquals($expected[0], "$actual[0]");
        $this->assertEquals($expected[1], "$actual[1]");
        $this->assertEquals($expected[2], "$actual[2]");
        $this->assertEquals($expected[3], "$actual[3]");

        $expected = 'C = PL, O = Urz\C4\85d Miasta Gdyni, serialNumber = PESEL: 61060603118, CN = Jerzy Przeworski, postalAddress = #30460C22416C2E204D6172737A61C5826B61205069C582737564736B6965676F2035322F35340C0D38312D333832204764796E69610C06506F6C736B610C09706F6D6F72736B6965, GN = Jerzy, SN = Przeworski';
        $this->assertEquals($expected, $x509->getSubjectDN(X509::DN_STRING));
    }

    public function testStrictComparison(): void
    {
        X509::addCA('-----BEGIN CERTIFICATE-----
MIIEbDCCA1SgAwIBAgIUJguKOMpJm/yRMDlMOW04NV0YPXowDQYJKoZIhvcNAQEF
BQAwYTELMAkGA1UEBhMCUEwxNzA1BgNVBAoTLkNaaUMgQ2VudHJhc3QgU0EgdyBp
bWllbml1IE1pbmlzdHJhIEdvc3BvZGFya2kxGTAXBgNVBAMTEENaaUMgQ2VudHJh
c3QgU0EwHhcNMDkwNDI5MTE1MzIxWhcNMTMxMjEzMjM1OTU5WjBzMQswCQYDVQQG
EwJQTDEoMCYGA1UEChMfS3Jham93YSBJemJhIFJvemxpY3plbmlvd2EgUy5BLjEk
MCIGA1UEAxMbQ09QRSBTWkFGSVIgLSBLd2FsaWZpa293YW55MRQwEgYDVQQFEwtO
ciB3cGlzdTogNjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIjNy3EL
oK0uKTqAJokiP8VIxER/0OfwhY4DBhJGW38W6Pfema8iUs4net0NgoIeDpMQ8IHj
FDSKkSaRkyL5f7PgvqBwzKe0HD1Duf9G/Lr2lu/J4QUMF3rqKaMRipXKkkEoKrub
Qe41/mPiPXeClNswNQUEyInqWpfWNncU8AIs2GKIFTfSNqK4PgWOY1kG9MYfoNVr
74dhejv7yHexEw9eAIcM1fIkEEq0vWIOjRtBXBAuWtUyD8iSeBs4nIN+614pHIjv
ncHxG7xTDbmOAVZFgGZ8Hk5CUseAtTpazQNdU66XRUuCj4km01L4wsfZ1X8tfYQA
6msMRYj+F7hLtoECAwEAAaOCAQgwggEEMA8GA1UdEwEB/wQFMAMBAf8wgY4GA1Ud
IwSBhjCBg4AU2a7r85Cp1iJNW0Ca1LR6VG3996ShZaRjMGExCzAJBgNVBAYTAlBM
MTcwNQYDVQQKEy5DWmlDIENlbnRyYXN0IFNBIHcgaW1pZW5pdSBNaW5pc3RyYSBH
b3Nwb2RhcmtpMRkwFwYDVQQDExBDWmlDIENlbnRyYXN0IFNBggQ9/0sQMDEGA1Ud
IAEB/wQnMCUwIwYEVR0gADAbMBkGCCsGAQUFBwIBFg13d3cubmNjZXJ0LnBsMA4G
A1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU3TGldJXipN4oGS3ZYmnBDMFs8gIwDQYJ
KoZIhvcNAQEFBQADggEBAJrkn3XycfimT5C6D+lYvQNB4/X44KZRhxhnplMOdr/V
3O13oJA/G2SkVaRZS1Rqy01vC9H3YSFfYnjFXJTOXldzodwszHEcGLHF/3JazHI9
BTpP1F4oFyd0Un/wkp1usGU4e1riU5RAlSp8YcMX3q+nOqyCh0JsxnP7LjauHkE3
KZ1RuBDZYbsYOwkAKjHax8srKugdWtq4sMNcqpxGFUah/4uLQn6hD4jeRpP4VGDv
HZDmxaIoJdmCxfn9XeIS5PcZR+mHHkUOIhYLnfdUp/T3Yxxo+XrrTckC6AjtsL5/
OA0vBLngVqqeuzVf0tUhcrCwPKQo5rKoakbApeXrows=
-----END CERTIFICATE-----');

        $x509 = X509::load('-----BEGIN CERTIFICATE-----
MIIFzzCCBLegAwIBAgIDAfdlMA0GCSqGSIb3DQEBBQUAMHMxCzAJBgNVBAYTAlBM
MSgwJgYDVQQKDB9LcmFqb3dhIEl6YmEgUm96bGljemVuaW93YSBTLkEuMSQwIgYD
VQQDDBtDT1BFIFNaQUZJUiAtIEt3YWxpZmlrb3dhbnkxFDASBgNVBAUTC05yIHdw
aXN1OiA2MB4XDTExMTEwOTA2MDAwMFoXDTEzMTEwOTA2MDAwMFowgdkxCzAJBgNV
BAYTAlBMMRwwGgYDVQQKDBNVcnrEhWQgTWlhc3RhIEdkeW5pMRswGQYDVQQFExJQ
RVNFTDogNjEwNjA2MDMxMTgxGTAXBgNVBAMMEEplcnp5IFByemV3b3Jza2kxTzBN
BgNVBBAwRgwiQWwuIE1hcnN6YcWCa2EgUGnFgnN1ZHNraWVnbyA1Mi81NAwNODEt
MzgyIEdkeW5pYQwGUG9sc2thDAlwb21vcnNraWUxDjAMBgNVBCoMBUplcnp5MRMw
EQYDVQQEDApQcnpld29yc2tpMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCM
m5vjGqHPthJCMqKpqssSISRos0PYDTcEQzyyurfX67EJWKtZj6HNwuDMEGJ02iBN
ZfjUl7r8dIi28bSKhNlsfycXZKYRcIjp0+r5RqtR2auo9GQ6veKb61DEAGIqaR+u
LLcJVTHCu0w9oXLGbRlGth5eNoj03CxXVAH2IfhbNwIDAQABo4IChzCCAoMwDAYD
VR0TAQH/BAIwADCCAUgGA1UdIAEB/wSCATwwggE4MIIBNAYJKoRoAYb3IwEBMIIB
JTCB3QYIKwYBBQUHAgIwgdAMgc1EZWtsYXJhY2phIHRhIGplc3Qgb8Wbd2lhZGN6
ZW5pZW0gd3lkYXdjeSwgxbxlIHRlbiBjZXJ0eWZpa2F0IHpvc3RhxYIgd3lkYW55
IGpha28gY2VydHlmaWthdCBrd2FsaWZpa293YW55IHpnb2RuaWUgeiB3eW1hZ2Fu
aWFtaSB1c3Rhd3kgbyBwb2RwaXNpZSBlbGVrdHJvbmljem55bSBvcmF6IHRvd2Fy
enlzesSFY3ltaSBqZWogcm96cG9yesSFZHplbmlhbWkuMEMGCCsGAQUFBwIBFjdo
dHRwOi8vd3d3Lmtpci5jb20ucGwvY2VydHlmaWthY2phX2tsdWN6eS9wb2xpdHlr
YS5odG1sMAkGA1UdCQQCMAAwIQYDVR0RBBowGIEWai5wcnpld29yc2tpQGdkeW5p
YS5wbDAOBgNVHQ8BAf8EBAMCBkAwgZ4GA1UdIwSBljCBk4AU3TGldJXipN4oGS3Z
YmnBDMFs8gKhd6R1MHMxCzAJBgNVBAYTAlBMMSgwJgYDVQQKDB9LcmFqb3dhIEl6
YmEgUm96bGljemVuaW93YSBTLkEuMSQwIgYDVQQDDBtDT1BFIFNaQUZJUiAtIEt3
YWxpZmlrb3dhbnkxFDASBgNVBAUTC05yIHdwaXN1OiA2ggJb9jBIBgNVHR8EQTA/
MD2gO6A5hjdodHRwOi8vd3d3Lmtpci5jb20ucGwvY2VydHlmaWthY2phX2tsdWN6
eS9DUkxfT1pLMzIuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQBYPIqnAreyeql7/opJ
jcar/qWZy9ruhB2q0lZFsJOhwgMnbQXzp/4vv93YJqcHGAXdHP6EO8FQX47mjo2Z
KQmi+cIHJHLONdX/3Im+M17V0iNAh7Z1lOSfTRT+iiwe/F8phcEaD5q2RmvYusR7
zXZq/cLL0If0hXoPZ/EHQxjN8pxzxiUx6bJAgturnIMEfRNesxwghdr1dkUjOhGL
f3kHVzgM6j3VAM7oFmMUb5y5s96Bzl10DodWitjOEH0vvnIcsppSxH1C1dCAi0o9
f/1y2XuLNhBNHMAyTqpYPX8Yvav1c+Z50OMaSXHAnTa20zv8UtiHbaAhwlifCelU
Mj93
-----END CERTIFICATE-----');
        $this->assertFalse($x509->validateSignature());
    }

    // fixed by #1104
    public function testMultipleDomainNames(): void
    {
        $privatekey = RSA::createKey(512)
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->withHash('sha1');
        $publickey = $privatekey->getPublicKey();

        $x509 = new X509($publickey);
        $x509->addDomains('example.com', 'example.net');
        $privatekey->sign($x509);

        self::assertTrue(true);
    }

    public function testUtcTimeWithoutSeconds(): void
    {
        $test = '-----BEGIN CERTIFICATE-----
MIIGFDCCBPygAwIBAgIDKCHVMA0GCSqGSIb3DQEBBQUAMIHcMQswCQYDVQQGEwJVUzEQMA4GA1UE
CBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTElMCMGA1UEChMcU3RhcmZpZWxkIFRlY2hu
b2xvZ2llcywgSW5jLjE5MDcGA1UECxMwaHR0cDovL2NlcnRpZmljYXRlcy5zdGFyZmllbGR0ZWNo
LmNvbS9yZXBvc2l0b3J5MTEwLwYDVQQDEyhTdGFyZmllbGQgU2VjdXJlIENlcnRpZmljYXRpb24g
QXV0aG9yaXR5MREwDwYDVQQFEwgxMDY4ODQzNTAcFwsxNDAxMDcwMDAwWhcNMTYwNDAxMDcwMDAw
WjCB6zETMBEGCysGAQQBgjc8AgEDEwJVUzEYMBYGCysGAQQBgjc8AgECEwdBcml6b25hMR0wGwYD
VQQPExRQcml2YXRlIE9yZ2FuaXphdGlvbjEUMBIGA1UEBRMLUi0xNzI0NzQxLTYxCzAJBgNVBAYT
AlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSQwIgYDVQQKExtTdGFy
ZmllbGQgVGVjaG5vbG9naWVzLCBMTEMxKzApBgNVBAMTInZhbGlkLnNmaS5jYXRlc3Quc3RhcmZp
ZWxkdGVjaC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCt1LHQOza9tkKxwGL+
/yKi/Fe5HM0sjvcM4ic1XVrvpewa4P/04IzGSjIGO3CXaSArxQMSzsTt2dcO9tSJ1Zk8c9NZXM8e
Vqx92iTMEf9OQcubWpzWmrPc3TAFhbVnfEmCptsXEgtxbAIbntrNeDk/hBPdl4DYFYRdm3ZTk4JM
If/quDZe5Oti53J0UsxWXSSoqKyPNdb671Q+OTQfSDj7kVF4+Ri3FIeAV16d2UnpBW1bgNqA5yIT
RskHE4bX98HDNHUTHioHpgA+fXfejWkGB/0FQN4HbZcysYHhf1L5cWBtz9w5J00YmjM5fzWvTc3U
UF9ou7m7JE4aqEbNOWb9AgMBAAGjggHOMIIByjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIF
oDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwLQYDVR0RBCYwJIIidmFsaWQuc2ZpLmNh
dGVzdC5zdGFyZmllbGR0ZWNoLmNvbTAdBgNVHQ4EFgQUcO+QEqZcHphPW9szww9ty+1AGmQwHwYD
VR0jBBgwFoAUSUtSJ9EbvPKhIWpie1FCeorX1VYwOAYDVR0fBDEwLzAtoCugKYYnaHR0cDovL2Ny
bC5zdGFyZmllbGR0ZWNoLmNvbS9zZnMzLTAuY3JsMIGNBggrBgEFBQcBAQSBgDB+MCoGCCsGAQUF
BzABhh5odHRwOi8vb2NzcC5zdGFyZmllbGR0ZWNoLmNvbS8wUAYIKwYBBQUHMAKGRGh0dHA6Ly9j
ZXJ0aWZpY2F0ZXMuc3RhcmZpZWxkdGVjaC5jb20vcmVwb3NpdG9yeS9zZl9pbnRlcm1lZGlhdGUu
Y3J0MFIGA1UdIARLMEkwRwYLYIZIAYb9bgEHFwMwODA2BggrBgEFBQcCARYqaHR0cDovL2NlcnRz
LnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBBQUAA4IBAQAViYkLUjQk
xWRmZl4DutL0/9/wJSURcJ1qunLP+TImJFp0A9RE/MNKZOmQoAEoH6hMg7FL4etkvTcnruTdcx+3
mvqYiECUiUEx6pkx3dmkYgZACEuk2nfyJ0MkV/zwzqmI8aV+kunpOQv93aePZbrBgaAzkE8jDlEx
td7c4pE7JF40jxmvDwjZHwpyNDULreGtFBij7JcWJCfihM3uetqrao0kOoeih1PQyJXtz2RldhFY
s6Jdk3ILYv+84t5UMO+aS9nVBXIcbgaGjIMZjHDgR/tE9FKFB66k8UTDzAwwEs38VV24zx6hlOzT
F7xAUxmPUnNb2teatMf2Rmj0fs+d
-----END CERTIFICATE-----
';

        $cert = X509::load($test);

        $this->assertEquals('2014-01-07 00:00:00', (string) $cert['tbsCertificate']['validity']['notBefore']['utcTime']);
        $this->assertEquals('2016-04-01 07:00:00', (string) $cert['tbsCertificate']['validity']['notAfter']['utcTime']);
    }

    public function testValidateURL(): void
    {
        $test = '-----BEGIN CERTIFICATE-----
MIIEgDCCA2igAwIBAgIIPUwrl6kGL2QwDQYJKoZIhvcNAQELBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTcxMDI0MDkwMjMxWhcNMTcxMjI5MDAwMDAw
WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDwFKTU
FgOf1beWoPUuJu8kbwmPBEAPIl933guV6XV54V0rtcc61DZplOzJO4uEyzcGxVqE
A9hKr0CAM/6jBQGZrKm5u6SyqXMPo3qEH2AxsbTx2eIeRIiAt3bDTq2eCilxyM/m
qOvEWAlXPPBFs2B7OBth0xuaSW8+XkNx5ZHIJrNqvh/6INbMVMRzRdQkxz72fiWn
fgtPAC4tBywmzUYTiboJW7poYqIZIxEZCKN0NdzKNOzKpIS1MByByQZECYDCsLVi
gkAuBdo4tT1QNU6KIqKvV716PhQU/ynQA/o7uzjgxO2p/KwaZyD/pihdfLv62qLg
jDBJMU9AfUCWxPmpAgMBAAGjggFLMIIBRzAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE
XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0
MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G
A1UdDgQWBBQAl7IbLVzwRb/SsW5jI3gdi7YCqjAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMCEGA1UdIAQaMBgwDAYKKwYBBAHW
eQIFATAIBgZngQwBAgIwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29n
bGUuY29tL0dJQUcyLmNybDANBgkqhkiG9w0BAQsFAAOCAQEAYJ+3TXE7etCjkLEE
/CN1BKGQVkYoCshZS3FkX8vUBP2orgvu9VGiLN9lb8+LMO+uNMVf+PLNsTP3lQ0q
oFzpU8xsv/87L7UcJoCge2ZR4kANgjmJ12TG7dCcPpbH2qu7Y8wnWubik5U68gsI
Qopg3hKg24p645o4exwsd/lOrsqh3vPorwZwU2Ekd2wKdxBID3puQA1jvWOBUcJI
Oe2K7+R2Cf6p8bYmm3OABuYkvO8D+u8gIdIO5cP+ic+SDOGVNJaT949YPes/S99R
9NQRFKcjEPl1UYh5bpPTKYzS7cTcDYG6xvbtG/XKEsK5U9UggzY6PCOPDDYpF+rq
C47x9g==
-----END CERTIFICATE-----';

        $x509 = X509::load($test);

        $this->assertTrue($x509->validateURL('https://www.google.com'));
    }

    /**
     * @group github1213
     */
    public function testValidateSignatureWithoutKeyIdentifier(): void
    {
        $x509 = X509::load('-----BEGIN CERTIFICATE-----
MIIDATCCAmqgAwIBAgICApowDQYJKoZIhvcNAQEFBQAwdzELMAkGA1UEBhMCVUsx
DzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQwwCgYDVQQKDANNUFMx
DDAKBgNVBAsMA0RldjENMAsGA1UEAwwEdGVzdDEbMBkGCSqGSIb3DQEJARYMZGVr
aUBtcHMuY29tMB4XDTE3MTEyNDE4MzE0MFoXDTE4MTEyNDE4MzE0MFowYTELMAkG
A1UEBhMCVUsxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQwwCgYD
VQQKDANNUFMxETAPBgNVBAsMCERldi90ZXN0MQ8wDQYDVQQDDAZ0ZXN0MDEwgZ8w
DQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ6+ydLXtjwbKhUBIodrm9Zq5yhhfMUM
IDhpcEZ2PAWWUiwKZOo9eyXGAv4LnpvDcX5GzThqI1g3/rcPjgBMOB8bcuQA6RE0
I9Jcf3YHbg/ednp7Q2X/zqUW+QUd01VfG8OJiRvO/4WKJTdQMU7/DKAv5WScIa4c
0b11X4iiLUVvAgMBAAGjgbEwga4wgZMGA1UdIwSBizCBiKF7pHkwdzELMAkGA1UE
BhMCVUsxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQwwCgYDVQQK
DANNUFMxDDAKBgNVBAsMA0RldjENMAsGA1UEAwwEdGVzdDEbMBkGCSqGSIb3DQEJ
ARYMZGVraUBtcHMuY29tggkA+Fj4n7pGuRMwCQYDVR0TBAIwADALBgNVHQ8EBAMC
BPAwDQYJKoZIhvcNAQEFBQADgYEAK0s83KbLM0OSj93/aly7UZHKGY3R/XhBNcsQ
3fcxzX6VX8naJpqfK9kM5Ry9IBnqu6LwCnk18kqt6V6PSjqQ3gj9S3x8znTMdus1
xraMNBOqRrn9quWCGEQt/iBrXHZ8zCdb4a+Eb5Jhz6/qK00KVufxw67fhuvhsjjv
nnA8of4=
-----END CERTIFICATE-----');

        $authorityKeyIdentifier = $x509->getExtension('id-ce-authorityKeyIdentifier');
        $this->assertNotNull($authorityKeyIdentifier);
        $this->assertFalse(isset($authorityKeyIdentifier['extnValue']['keyIdentifier']));

        X509::addCA('-----BEGIN CERTIFICATE-----
MIIDITCCAoqgAwIBAgIJAPhY+J+6RrkTMA0GCSqGSIb3DQEBBQUAMHcxCzAJBgNV
BAYTAlVLMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEMMAoGA1UE
CgwDTVBTMQwwCgYDVQQLDANEZXYxDTALBgNVBAMMBHRlc3QxGzAZBgkqhkiG9w0B
CQEWDGRla2lAbXBzLmNvbTAeFw0xNzExMjQxODI3NDlaFw0xODExMjQxODI3NDla
MHcxCzAJBgNVBAYTAlVLMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRv
bjEMMAoGA1UECgwDTVBTMQwwCgYDVQQLDANEZXYxDTALBgNVBAMMBHRlc3QxGzAZ
BgkqhkiG9w0BCQEWDGRla2lAbXBzLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEA022CwduFLxKCwwKp2WTTpBu1vhcVywOAW0rNIfuSa7XsYyX5rCSScE4d
YW8hUgWbZSoJMk1s1omZarmwMAIeknpigZSKWUhEJF3IVnc1tW3mGaSAEvKg6r4g
unKttJV2aDW8w3Ew2qzP0G8sJwMX7y49XQumG5IgpuVXkiydTwsCAwEAAaOBtDCB
sTCBkwYDVR0jBIGLMIGIoXukeTB3MQswCQYDVQQGEwJVSzEPMA0GA1UECAwGTG9u
ZG9uMQ8wDQYDVQQHDAZMb25kb24xDDAKBgNVBAoMA01QUzEMMAoGA1UECwwDRGV2
MQ0wCwYDVQQDDAR0ZXN0MRswGQYJKoZIhvcNAQkBFgxkZWtpQG1wcy5jb22CCQD4
WPifuka5EzAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIE8DANBgkqhkiG9w0BAQUF
AAOBgQBNhIESJpRiYBPDdIsdfOyuclzmN+5KHXicAXN4WXFiYgVQhML44Vb7Macb
X5ZBGsa3olRvoKrhg8ian7NyfRviAk0iO8EAAFCeeYHPN6bbloGfUcuf72P8576w
HI8pYRZmT7tKW3HxlZLJGGVo5CgBawdiWngK5v+LwWiNRTqxJA==
-----END CERTIFICATE-----');

        X509::setTargetValidationDate(null);
        $this->assertTrue($x509->validateSignature());
    }

    /**
     * @group github1213
     */
    public function testValidateSignatureSelfSignedWithoutKeyIdentifier(): void
    {
        $x509 = X509::load('-----BEGIN CERTIFICATE-----
MIIDITCCAoqgAwIBAgIJAPhY+J+6RrkTMA0GCSqGSIb3DQEBBQUAMHcxCzAJBgNV
BAYTAlVLMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEMMAoGA1UE
CgwDTVBTMQwwCgYDVQQLDANEZXYxDTALBgNVBAMMBHRlc3QxGzAZBgkqhkiG9w0B
CQEWDGRla2lAbXBzLmNvbTAeFw0xNzExMjQxODI3NDlaFw0xODExMjQxODI3NDla
MHcxCzAJBgNVBAYTAlVLMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRv
bjEMMAoGA1UECgwDTVBTMQwwCgYDVQQLDANEZXYxDTALBgNVBAMMBHRlc3QxGzAZ
BgkqhkiG9w0BCQEWDGRla2lAbXBzLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEA022CwduFLxKCwwKp2WTTpBu1vhcVywOAW0rNIfuSa7XsYyX5rCSScE4d
YW8hUgWbZSoJMk1s1omZarmwMAIeknpigZSKWUhEJF3IVnc1tW3mGaSAEvKg6r4g
unKttJV2aDW8w3Ew2qzP0G8sJwMX7y49XQumG5IgpuVXkiydTwsCAwEAAaOBtDCB
sTCBkwYDVR0jBIGLMIGIoXukeTB3MQswCQYDVQQGEwJVSzEPMA0GA1UECAwGTG9u
ZG9uMQ8wDQYDVQQHDAZMb25kb24xDDAKBgNVBAoMA01QUzEMMAoGA1UECwwDRGV2
MQ0wCwYDVQQDDAR0ZXN0MRswGQYJKoZIhvcNAQkBFgxkZWtpQG1wcy5jb22CCQD4
WPifuka5EzAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIE8DANBgkqhkiG9w0BAQUF
AAOBgQBNhIESJpRiYBPDdIsdfOyuclzmN+5KHXicAXN4WXFiYgVQhML44Vb7Macb
X5ZBGsa3olRvoKrhg8ian7NyfRviAk0iO8EAAFCeeYHPN6bbloGfUcuf72P8576w
HI8pYRZmT7tKW3HxlZLJGGVo5CgBawdiWngK5v+LwWiNRTqxJA==
-----END CERTIFICATE-----');

        $authorityKeyIdentifier = $x509->getExtension('id-ce-authorityKeyIdentifier');
        $this->assertNotNull($authorityKeyIdentifier);
        $this->assertFalse(isset($authorityKeyIdentifier['extnValue']['keyIdentifier']));

        $this->assertTrue($x509->validateSignature(false));
    }

    /**
     * @group github1243
     */
    public function testExtensionRemoval(): void
    {
        // Load the CA and its private key.
        $pemcakey = '-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCpKtNFBdtRd8eFcq7L7RxvkeeUFcc4QDY6rLDJUpPGp1qL9L7p
l+rK0L66TGSs+wZTM4awDP2d75HZG2/9LOX5Xy4oAb7aS2PiLDQmVa81t1sA42bs
3UBxak9w4jcj623gesDG6dN1sFpqVq9/Z4JOnPJu1PXzwcuj3t7J5QLFSwIDAQAB
AoGBAI8/vHeOZhGupD3Uxz/YIWQ44Sj86B4yAbnd0jYovwpRXNN3BNM52ZC1A00u
s3Hnf4uk7kDWP00mORLnsQVqp7IKMznTHyvBJ/uA5vipXc0fmpmmPLjy6Sh071Co
0iTYFUDu3dlPi6UEgQ6ZjgXmHdeTRA/YuH/70sqKjLjkYRbBAkEA3oRoMdJjJAm4
+XY3+1Ulc2qTHkecsTOON0Reta9THws4ibtKIP89aBUthz1XGLm9mUtWu49kQXht
o1FtFLhLtQJBAMKfUurb075FQIRl6KsRJilCWVJSplf0szvKWm40uDXYmFlj7D7J
bEdbVBWdfBi9SNzZrLAThjfxwdBsr+DjbP8CQQCeft+cxUfazpYUErHTcxXG/R2n
jsi8q4VcNnXjoetqDFsMN/yYPlYmAhe44edc9EhpnXE9DekSfU5S61fwT0mVAkAm
keSg3sfr4VWT545guJlTe+6vvelxbPFIXCXnyVLoePBYZtEe8FQhIBxd3EQHsxuJ
iSoMCxKCa8r5P1DrxKaJAkBBP87OdahRq0CBQjTFg0wmPs66PoTXA4hZvSxV77CO
tMPj6Pas7Muejogm6JkmxXC/uT6Tzfknd0B3XSmtDzGL
-----END RSA PRIVATE KEY-----';
        $cakey = PublicKeyLoader::load($pemcakey)
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->withHash('sha1');
        $pemca = '-----BEGIN CERTIFICATE-----
MIICADCCAWmgAwIBAgIUJXQulcz5xkTam8UGC/yn6iVaiWwwDQYJKoZIhvcNAQEF
BQAwHDEaMBgGA1UECgwRcGhwc2VjbGliIGRlbW8gQ0EwHhcNMTgwMTIxMTc0NzM0
WhcNMTkwMTIxMTc0NzM0WjAcMRowGAYDVQQKDBFwaHBzZWNsaWIgZGVtbyBDQTCB
nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqSrTRQXbUXfHhXKuy+0cb5HnlBXH
OEA2OqywyVKTxqdai/S+6ZfqytC+ukxkrPsGUzOGsAz9ne+R2Rtv/Szl+V8uKAG+
2ktj4iw0JlWvNbdbAONm7N1AcWpPcOI3I+tt4HrAxunTdbBaalavf2eCTpzybtT1
88HLo97eyeUCxUsCAwEAAaM/MD0wCwYDVR0PBAQDAgEGMA8GA1UdEwEB/wQFMAMB
Af8wHQYDVR0OBBYEFCS1BJ12nN8ObQWE4OgOOSH9DxTRMA0GCSqGSIb3DQEBBQUA
A4GBAHkSnlJnlkwDEUcENKWFZpfNgZu9HUvEuLDVOnhvsdd2MDr8EbVbgMHYNWnV
+ZOS/dqbuCd9Vd27JsBC2YHklaq9/V5zMbrEBiMLo5P5WL9qrz0qbmK/aruP+VX7
cKVMm1WnOQd4aQgCvzv2r7/gsdX++496vRpBMTfwa1qLBjG6
-----END CERTIFICATE-----';
        $ca = X509::load($pemca);

        // Read the old certificate.
        X509::addCA($pemca);
        $cert = X509::load('-----BEGIN CERTIFICATE-----
MIIB+TCCAWKgAwIBAgIUW+D7X27oKXHaD6WqFjelccV+D4YwDQYJKoZIhvcNAQEF
BQAwHDEaMBgGA1UECgwRcGhwc2VjbGliIGRlbW8gQ0EwHhcNMTgwMTIxMTc0NzM0
WhcNMTkwMTIxMTc0NzM0WjA3MRwwGgYDVQQKDBNwaHBzZWNsaWIgZGVtbyBjZXJ0
MRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEAqnB0IyO+O6RcZdZooFaMKY/ggeNPXW/EaLXdciHEnzxgbsVb1I5m5pwy
nZIf6RCHUsfOYdhTX/xQE8JOSkbDEYtKmrySxu+JpmR3qZPhL+4rJUJKCdI+9YbM
z1wiqQeHhVUTPiEvgdAzkzPXcrkLmpb1KV7VhKoQ4Z3swmJX528CAwEAAaMdMBsw
GQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20wDQYJKoZIhvcNAQEFBQADgYEAV5W5
G9eY1SJiwIHMcd5Eo41w+bN69EqOJhTY28LQc/m9i+Fuc1J6nkwDMKCtEeEUyhjl
bEbVUszdgPQWON7Y2nS5OCb2BevxW8Xdf6gnf/PRRYmlZJgygwf0KpgSm5CxxsZW
Fqfy+n5VpXOdrjic4yZ52yS5sUaq05s6ZZvnmdU=
-----END CERTIFICATE-----');
        $this->assertTrue($cert->validateSignature());
        $cert->setStartDate('-1 day');
        $cert->setEndDate('+2 years');
        $cert->removeExtension('id-ce-subjectAltName');
        $cert->addDomains('www.google.com');
        $cakey->sign($cert);

        $this->assertIsString("$cert");
    }

    // this test will fail without an active internet connection
    public function testAuthorityInfoAccess(): void
    {
        X509::addCA('-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----');
        $x509 = X509::load('-----BEGIN CERTIFICATE-----
MIIG3TCCBcWgAwIBAgIQAtB7LVsRCmgbyWiiw7Sf5jANBgkqhkiG9w0BAQsFADBN
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E
aWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTcwOTEzMDAwMDAwWhcN
MTkwOTEzMTIwMDAwWjBqMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
aW9uMRQwEgYDVQQDEwtvdXRsb29rLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAIz2tovvgBmK4sOHgpyzCdtXrI0XOujctf6LHMj16wzUnMEatioS
tH0Pz0dKkCr/0yd9qtXbGhD1o6WhFsd7k651K9MZ98+uQ29SzTIAl6y1gkaBbp4h
MFXcE5EpRNHHmK8t2OR7hzmrvvNr6OTYv7BhVCw9pSrQqEFNno0K2TQRhAD9uzrL
OY+rBBVedCXWXH7uhZoZ6joUU7CEA5pPMzKPL1ro+Eorc8vt5FYOC+oAT587+b1M
z+jbZVQlq0qaMkBKRtUIII78MYY0n8DopGqHyzwqWoGySHJNC8256q+MwsZQvvQ3
vmy/rf61h2sg1tU0s7O88Yufxp0LSaMMzZcCAwEAAaOCA5owggOWMB8GA1UdIwQY
MBaAFA+AYRyCMWHVLyjnjUY4tCzhxtniMB0GA1UdDgQWBBT7hLoZ/03rqwcslIc2
0k0z2R+vNTCCAdwGA1UdEQSCAdMwggHPggtvdXRsb29rLmNvbYIWKi5jbG8uZm9v
dHByaW50ZG5zLmNvbYIWKi5ucmIuZm9vdHByaW50ZG5zLmNvbYIgYXR0YWNobWVu
dC5vdXRsb29rLm9mZmljZXBwZS5uZXSCG2F0dGFjaG1lbnQub3V0bG9vay5saXZl
Lm5ldIIdYXR0YWNobWVudC5vdXRsb29rLm9mZmljZS5uZXSCHWNjcy5sb2dpbi5t
aWNyb3NvZnRvbmxpbmUuY29tgiFjY3Mtc2RmLmxvZ2luLm1pY3Jvc29mdG9ubGlu
ZS5jb22CC2hvdG1haWwuY29tgg0qLmhvdG1haWwuY29tggoqLmxpdmUuY29tghZt
YWlsLnNlcnZpY2VzLmxpdmUuY29tgg1vZmZpY2UzNjUuY29tgg8qLm9mZmljZTM2
NS5jb22CFyoub3V0bG9vay5vZmZpY2UzNjUuY29tgg0qLm91dGxvb2suY29tghYq
LmludGVybmFsLm91dGxvb2suY29tggwqLm9mZmljZS5jb22CEm91dGxvb2sub2Zm
aWNlLmNvbYIUc3Vic3RyYXRlLm9mZmljZS5jb22CGHN1YnN0cmF0ZS1zZGYub2Zm
aWNlLmNvbTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG
AQUFBwMCMGsGA1UdHwRkMGIwL6AtoCuGKWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
bS9zc2NhLXNoYTItZzEuY3JsMC+gLaArhilodHRwOi8vY3JsNC5kaWdpY2VydC5j
b20vc3NjYS1zaGEyLWcxLmNybDBMBgNVHSAERTBDMDcGCWCGSAGG/WwBATAqMCgG
CCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAEC
AjB8BggrBgEFBQcBAQRwMG4wJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
ZXJ0LmNvbTBGBggrBgEFBQcwAoY6aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
L0RpZ2lDZXJ0U0hBMlNlY3VyZVNlcnZlckNBLmNydDAMBgNVHRMBAf8EAjAAMA0G
CSqGSIb3DQEBCwUAA4IBAQA3zjN7I6jTeL+08nhG5eAY0q4pLY40bCQHqONBLSI3
uRmQFUfrQOPYBqLC1QU+J2Z2HcX7YiqE3WAR3ODS9g2BAVXkKOQKNBnr2hKwueOz
qPwyvTyzcIQYUw+SrTX+bfJwYMTmZvtP9S7/pB1jPhrV7YGsD55AI9bGa9cmH7VQ
OiL1p5Qovg5KRsldoZeC04OF/UQIR1fv47VGptsHHGypvSo1JinJFQMXylqLIrUW
lV66p3Ui7pFABGc/Lv7nOyANXfLugBO8MyzydGA4NRGiS2MbGpswPCg154pWausU
M0qaEPsM2o3CSTfxSJQQIyEe+izV3UQqYSyWkNqCCFPN
-----END CERTIFICATE-----');

        X509::setRecurLimit(0);
        $this->assertFalse($x509->validateSignature());

        X509::setRecurLimit(5);
        $this->assertTrue($x509->validateSignature());
    }

    public function testValidateDate(): void
    {
        $x509 = X509::load('-----BEGIN CERTIFICATE-----
MIIDITCCAoqgAwIBAgIQT52W2WawmStUwpV8tBV9TTANBgkqhkiG9w0BAQUFADBM
MQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkg
THRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0xMTEwMjYwMDAwMDBaFw0x
MzA5MzAyMzU5NTlaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
MRYwFAYDVQQHFA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKFApHb29nbGUgSW5jMRcw
FQYDVQQDFA53d3cuZ29vZ2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEA3rcmQ6aZhc04pxUJuc8PycNVjIjujI0oJyRLKl6g2Bb6YRhLz21ggNM1QDJy
wI8S2OVOj7my9tkVXlqGMaO6hqpryNlxjMzNJxMenUJdOPanrO/6YvMYgdQkRn8B
d3zGKokUmbuYOR2oGfs5AER9G5RqeC1prcB6LPrQ2iASmNMCAwEAAaOB5zCB5DAM
BgNVHRMBAf8EAjAAMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwudGhhd3Rl
LmNvbS9UaGF3dGVTR0NDQS5jcmwwKAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUF
BwMCBglghkgBhvhCBAEwcgYIKwYBBQUHAQEEZjBkMCIGCCsGAQUFBzABhhZodHRw
Oi8vb2NzcC50aGF3dGUuY29tMD4GCCsGAQUFBzAChjJodHRwOi8vd3d3LnRoYXd0
ZS5jb20vcmVwb3NpdG9yeS9UaGF3dGVfU0dDX0NBLmNydDANBgkqhkiG9w0BAQUF
AAOBgQAhrNWuyjSJWsKrUtKyNGadeqvu5nzVfsJcKLt0AMkQH0IT/GmKHiSgAgDp
ulvKGQSy068Bsn5fFNum21K5mvMSf3yinDtvmX3qUA12IxL/92ZzKbeVCq3Yi7Le
IOkKcGQRCMha8X2e7GmlpdWC1ycenlbN0nbVeSv3JUMcafC4+Q==
-----END CERTIFICATE-----');

        $this->assertFalse($x509->validateDate('Nov 22, 2018'));
        $this->assertTrue($x509->validateDate('Nov 22, 2012'));
    }

    public function testDSALoad(): void
    {
        X509::clearCAStore();
        X509::setTargetValidationDate(null);

        // openssl dsaparam -out params.pem 3072
        // openssl gendsa -out key.pem params.pem
        // openssl req -new -key key.pem -out req.pem
        // openssl x509 -req -in req.pem -signkey key.pem -out certificate.cer

        $x509 = X509::load('-----BEGIN CERTIFICATE-----
MIIF6jCCBZACCQDH427nRymbrDALBglghkgBZQMEAwIwRTELMAkGA1UEBhMCQVUx
EzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMg
UHR5IEx0ZDAeFw0xOTA1MjEwMjE2NTVaFw0xOTA2MjAwMjE2NTVaMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwggTGMIIDOQYHKoZIzjgEATCCAywCggGBAMLpmurU070o
PR1F7HgKror1KV8hL8ipiH9F1PxDp+GOhK8qBVIT355xdt6icQSHwQ3ZPuQzzm42
FKZvLBHtU+UaPwWGOtjjGt7VXGawl1kVudwZ0du7gzvtcScynn09DhsaC3XEiDy6
9CVrPbUck0/TyIzjr0czblRw6znaMoYGW/UlkKF+v86cmx200ASWawuW00QhiRD9
cvoN23TgxZKNachi/2o1TCQ5UIRNUBR6Z50q3cXMIMzmSXl/8TKii655zWdda+au
ecf/GomjJUpaw/7QMzCwgYH18rZdjO2VocUhpbkitayFrjbIaxLmUTLF080GfweX
AUGcMYb6M+9hYey5xEyPLtWcmD0lvFwlOhIHSncKiDsYQLQqRyBRsSQ5wIq2u3Zi
L5f7Jeb/rBF5knt7UhmA/QHYZPUidJFEfgbnm/XTt0I+Ykw9Olkvwx+hwH+552Ox
owIs05XeMwdDUA50HhlLtzLLfU+Hi1LThX/B3Y70i0Z7UjkiS8IBGwIhAN7DyxFC
zsD/nMXC5GKLVjmQATu8wSE0fBtJCTPlCAJdAoIBgCbZ9mTLiVmHwPvzf2Ii5+B4
Acm/OUR0PvOtg7Qp1A0IG3PSyQkbxNySxjxN4kBT/3w2vroLiuRhXc6tenhCWnPv
ZJBbO8XyfI/kcoTxjHC33XWXGuUkCKBHlOupmtdEVcFTkC3LYdEcWgTZ7b8CKaeH
kDvJnmgkkz6OCXO8r5TPAYjh5HCTJkLen5RPKJL9426fNAZJaXz7Zxydisuk7ymY
jTxyPpb1AkV06a/iEFavSzrKi9KSQxvVoSXij18bm9SWzXPZeai6NHd0ZUpwqR0e
Tt784FmpD862YFWcahzbVObY7+JBX9v9H4kTcO7nophKK2BiLDagoqZMSkW8oSOL
4DU0F8K8UkHjtuiLXw40bE9j2uyPqB9UCJ4qygXq0XkTZHuCSfSvGyA16yWobZOV
0szio1/4l6EpmPKYpy1nZ2dk9vEgm4eXxZuhZlmyPTiC6rPGzEHrHkc56SK8Kn8k
sy8Udvsgzr8+UpkN3rBQvgHrEfJnuNTmPGQbLyBukwOCAYUAAoIBgBxS7Ghb6ujq
FFln6AlFL2OrpUrB9q8NZH84o+ygP39Kf/FdJ7CRs4dRL7L0FdruimK6Vsm55rPJ
DSCaDZD45p2deG6mFmdpVAtiDPqOWMm6zGXjU4HhNA70oVOGQ7HkIlRWvbkYPA3z
qT7Ibqe8gFaIkqobCEwQudcoqDlK+5vnO1IYt5zwuy6oeCN9rixaWjRLPm65SKzc
+4l9+XAZWThoKlFL3wVmuZ/3EeYX0G8FAR7nYEFwSTrGQTCAmTMVgYi9TxDLqGMe
M6Nkp2R90dadRBqt6MJ/lZ3jOzgUw4dF9ofIumUJ0Up9sWDPEB96Ng69ZPWbXNo6
799zo1mN2GaxQHfyn6VWjNf649eBg5Q3aNHjOSz9wi9afjs3u44AnBdGdZzlKVXX
obtpt4Nwq9elof+9iwdjKqki6A9h0NWS1w9zjZ21n3Yq69J/XQl0UYYykGSWz65D
bFuYoWPMpfSxEnxDZL5O3nxBCQDlPRxEjKwG/TdKxIJAuhPlgkgknzALBglghkgB
ZQMEAwIDRwAwRAIgJPiEjjf2EMdvVuu5dkxR6OpVdbHST9pWTAUVa0ZMeuYCIBLX
pMAUPdvLhVjjTvw4ypYrNMc4Z3z5n3bfCVzIQL5Z
-----END CERTIFICATE-----');

        $this->assertEquals('id-dsa-with-sha256', $x509['tbsCertificate']['signature']['algorithm']);
        $this->assertInstanceOf(DSA::class, $x509['tbsCertificate']['subjectPublicKeyInfo']);
        $this->assertEquals('id-dsa-with-sha256', $x509['signatureAlgorithm']['algorithm']);

        $this->assertTrue($x509->validateSignature(false));
    }

    public function testECLoad(): void
    {
        X509::clearCAStore();
        X509::setTargetValidationDate(null);

        // openssl req -x509 -nodes -days 3650 -newkey ec:<(openssl ecparam -name prime256v1) -keyout ecdsakey.pem -out ecdsacert.pem

        $x509 = X509::load('-----BEGIN CERTIFICATE-----
MIIB0zCCAXqgAwIBAgIJAIUvi6ecHYnoMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQwHhcNMTkwNTIxMDIxOTMyWhcNMjkwNTE4MDIxOTMyWjBFMQsw
CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu
ZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXYOR
ZYFctekS6LIey8va5CLkQCWZw8JMIRPyWkABB6tjx5xJr8MgYiXB0nS15HC82JYN
fR6NAT6lSnbpcfBgJKNTMFEwHQYDVR0OBBYEFEReRoJtjUXYus7iJWM/T1J7YxVH
MB8GA1UdIwQYMBaAFEReRoJtjUXYus7iJWM/T1J7YxVHMA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwIDRwAwRAIgIBo2fgqfVsbKczXodiXamRIv1vmqgo3pIGzV
f11dQP8CIDoB2AbvB3Yk/iGduWpw+3FwNAZ1y/rTqQK6+XgZCt6K
-----END CERTIFICATE-----');

        $this->assertEquals('ecdsa-with-SHA256', $x509['tbsCertificate']['signature']['algorithm']);
        $this->assertInstanceOf(EC::class, $x509['tbsCertificate']['subjectPublicKeyInfo']);
        $this->assertEquals('ecdsa-with-SHA256', $x509['signatureAlgorithm']['algorithm']);

        $this->assertTrue($x509->validateSignature(false));
    }

    public function testPSSLoad(): void
    {
        X509::clearCAStore();
        X509::setTargetValidationDate(null);

        // openssl genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha512 -pkeyopt rsa_pss_keygen_saltlen:5 -out CA.priKey
        // openssl req -x509 -new -key CA.priKey -subj "/CN=CA" -sha256 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha512 -pkeyopt rsa_pss_keygen_saltlen:5 -out CA.cer

        $x509 = X509::load('-----BEGIN CERTIFICATE-----
MIIDizCCAkOgAwIBAgIUZe4gqXJqqyKvQDBxcbAuPdttxTQwPQYJKoZIhvcNAQEK
MDCgDTALBglghkgBZQMEAgGhGjAYBgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIDogMC
AQUwDTELMAkGA1UEAwwCQ0EwHhcNMTkwNTA5MDI0MTI0WhcNMTkwNjA4MDI0MTI0
WjANMQswCQYDVQQDDAJDQTCCAVIwPQYJKoZIhvcNAQEKMDCgDTALBglghkgBZQME
AgGhGjAYBgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIDogMCAQUDggEPADCCAQoCggEB
AOB5e+yI4nAfiDdhignByF9Hw9BOjCeRk++9m5iSKaZdkzFLPtR3uMw+x+B9xChq
kro/jG1ierEP8YISEDe6wXIRmuSunC1/wqy8oX0xfo23jE7gdSpjk+9cF1cVABPh
ehwcGmzuXeOv/M4iQr41MK8hdqAVJRIA8O7kZuQxpEbLBKsQc9u0eEFrNVf5jYGj
7vsCpW/XmZYaNWQaOK5Psd0rxVaz2CYYG2RiXq2wQiHrFtwOVJAhuHXlOmr4ZjuR
NJLNnHjqkIaRv+JU2VCwPHcbIK4vO7EL7PKVa6g5WY33SzF3aqE7hCk6JeZ4KSSh
i5dq4bRiGpGp1BzrU/t/XTkCAwEAAaNTMFEwHQYDVR0OBBYEFOWZWROhub/avDzR
hDc5biqHzkrYMB8GA1UdIwQYMBaAFOWZWROhub/avDzRhDc5biqHzkrYMA8GA1Ud
EwEB/wQFMAMBAf8wPQYJKoZIhvcNAQEKMDCgDTALBglghkgBZQMEAgGhGjAYBgkq
hkiG9w0BAQgwCwYJYIZIAWUDBAIDogMCAQUDggEBANAoXtrOunHHlrEWNhj8xvwB
pMa3N66PO3wQ/nax73s+xCF57haXjh8mBkDy6DsvctHSyV8RgXQUXaprDLtNA+F3
JIgUNfP4znO98cdQ3tkANvtWA5YuyhyNq9xDzH6LsLB6cZfqPrvFGuvhCmGT9qCk
OKmHrFklewl1sfwIQzK+hHeimaUSrb6SIYYenbvH5XI9vjbA/jojlvIc1mz7Pzmr
9idg8ckxvQ5K3Y01UNBg2vOSaInp+G7N7XlEMERssq6ALMaPm4GrXUlO0cs/mQXd
edu9tyNNr2vvZjshoY5y58+hVIjee/Pzxa7GX0LDEmK8FdFBxWeNx0g/TsZj6GE=
-----END CERTIFICATE-----');

        $this->assertEquals('id-RSASSA-PSS', $x509['tbsCertificate']['signature']['algorithm']);
        $this->assertInstanceOf(RSA::class, $x509['tbsCertificate']['subjectPublicKeyInfo']);
        $this->assertEquals('id-RSASSA-PSS', $x509['signatureAlgorithm']['algorithm']);

        $this->assertTrue($x509->validateSignature(false));
    }

    public function testDSASave(): void
    {
        $private = '-----BEGIN DSA PRIVATE KEY-----
MIIE1QIBAAKCAYEAwuma6tTTvSg9HUXseAquivUpXyEvyKmIf0XU/EOn4Y6EryoF
UhPfnnF23qJxBIfBDdk+5DPObjYUpm8sEe1T5Ro/BYY62OMa3tVcZrCXWRW53BnR
27uDO+1xJzKefT0OGxoLdcSIPLr0JWs9tRyTT9PIjOOvRzNuVHDrOdoyhgZb9SWQ
oX6/zpybHbTQBJZrC5bTRCGJEP1y+g3bdODFko1pyGL/ajVMJDlQhE1QFHpnnSrd
xcwgzOZJeX/xMqKLrnnNZ11r5q55x/8aiaMlSlrD/tAzMLCBgfXytl2M7ZWhxSGl
uSK1rIWuNshrEuZRMsXTzQZ/B5cBQZwxhvoz72Fh7LnETI8u1ZyYPSW8XCU6EgdK
dwqIOxhAtCpHIFGxJDnAira7dmIvl/sl5v+sEXmSe3tSGYD9Adhk9SJ0kUR+Bueb
9dO3Qj5iTD06WS/DH6HAf7nnY7GjAizTld4zB0NQDnQeGUu3Mst9T4eLUtOFf8Hd
jvSLRntSOSJLwgEbAiEA3sPLEULOwP+cxcLkYotWOZABO7zBITR8G0kJM+UIAl0C
ggGAJtn2ZMuJWYfA+/N/YiLn4HgByb85RHQ+862DtCnUDQgbc9LJCRvE3JLGPE3i
QFP/fDa+uguK5GFdzq16eEJac+9kkFs7xfJ8j+RyhPGMcLfddZca5SQIoEeU66ma
10RVwVOQLcth0RxaBNntvwIpp4eQO8meaCSTPo4Jc7yvlM8BiOHkcJMmQt6flE8o
kv3jbp80BklpfPtnHJ2Ky6TvKZiNPHI+lvUCRXTpr+IQVq9LOsqL0pJDG9WhJeKP
Xxub1JbNc9l5qLo0d3RlSnCpHR5O3vzgWakPzrZgVZxqHNtU5tjv4kFf2/0fiRNw
7ueimEorYGIsNqCipkxKRbyhI4vgNTQXwrxSQeO26ItfDjRsT2Pa7I+oH1QInirK
BerReRNke4JJ9K8bIDXrJahtk5XSzOKjX/iXoSmY8pinLWdnZ2T28SCbh5fFm6Fm
WbI9OILqs8bMQeseRznpIrwqfySzLxR2+yDOvz5SmQ3esFC+AesR8me41OY8ZBsv
IG6TAoIBgBxS7Ghb6ujqFFln6AlFL2OrpUrB9q8NZH84o+ygP39Kf/FdJ7CRs4dR
L7L0FdruimK6Vsm55rPJDSCaDZD45p2deG6mFmdpVAtiDPqOWMm6zGXjU4HhNA70
oVOGQ7HkIlRWvbkYPA3zqT7Ibqe8gFaIkqobCEwQudcoqDlK+5vnO1IYt5zwuy6o
eCN9rixaWjRLPm65SKzc+4l9+XAZWThoKlFL3wVmuZ/3EeYX0G8FAR7nYEFwSTrG
QTCAmTMVgYi9TxDLqGMeM6Nkp2R90dadRBqt6MJ/lZ3jOzgUw4dF9ofIumUJ0Up9
sWDPEB96Ng69ZPWbXNo6799zo1mN2GaxQHfyn6VWjNf649eBg5Q3aNHjOSz9wi9a
fjs3u44AnBdGdZzlKVXXobtpt4Nwq9elof+9iwdjKqki6A9h0NWS1w9zjZ21n3Yq
69J/XQl0UYYykGSWz65DbFuYoWPMpfSxEnxDZL5O3nxBCQDlPRxEjKwG/TdKxIJA
uhPlgkgknwIgdDqqKIAF60ouiynsbU53ERS0TwpjeFiYGA48SwYW3Nk=
-----END DSA PRIVATE KEY-----';
        $private = PublicKeyLoader::load($private);
        $x509 = new X509($private->getPublicKey());
        $x509->addDNProp('id-at-organizationName', 'phpseclib demo cert');
        $private->sign($x509);
        $x509 = "$x509";

        $this->assertIsString($x509);

        $x509 = X509::load($x509);
        $this->assertEquals('id-dsa-with-sha256', $x509['tbsCertificate']['signature']['algorithm']);
        $this->assertInstanceOf(DSA::class, $x509['tbsCertificate']['subjectPublicKeyInfo']);
        $this->assertEquals('id-dsa-with-sha256', $x509['signatureAlgorithm']['algorithm']);
    }

    public function testECSave(): void
    {
        $private = '-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQ0o1byJQbAcuklBt
MENv2e0W3cE6gRmETxEvTBAxRTShRANCAARdg5FlgVy16RLosh7Ly9rkIuRAJZnD
wkwhE/JaQAEHq2PHnEmvwyBiJcHSdLXkcLzYlg19Ho0BPqVKdulx8GAk
-----END PRIVATE KEY-----';
        $private = PublicKeyLoader::load($private);
        $x509 = new X509($private->getPublicKey());
        $x509->addDNProp('id-at-organizationName', 'phpseclib demo cert');
        $private->sign($x509);
        $x509 = "$x509";

        $this->assertIsString($x509);

        $x509 = X509::load($x509);
        $this->assertEquals('ecdsa-with-SHA256', $x509['tbsCertificate']['signature']['algorithm']);
        $this->assertInstanceOf(EC::class, $x509['tbsCertificate']['subjectPublicKeyInfo']);
        $this->assertEquals('ecdsa-with-SHA256', $x509['signatureAlgorithm']['algorithm']);
    }

    public function testPSSSave(): void
    {
        $private = '-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=
-----END RSA PRIVATE KEY-----';
        $private = PublicKeyLoader::load($private);
        $x509 = new X509($private->getPublicKey());
        $x509->addDNProp('id-at-organizationName', 'phpseclib demo cert');
        $private->sign($x509);
        $x509 = "$x509";

        $this->assertIsString($x509);

        $x509 = X509::load($x509)->toArray();
        $this->assertEquals('id-RSASSA-PSS', $x509['tbsCertificate']['signature']['algorithm']);
        $this->assertArrayHasKey('parameters', $x509['tbsCertificate']['signature']);
        $this->assertInstanceOf(RSA::class, $x509['tbsCertificate']['subjectPublicKeyInfo']);
        $this->assertEquals('id-RSASSA-PSS', $x509['signatureAlgorithm']['algorithm']);
        $this->assertArrayHasKey('parameters', $x509['signatureAlgorithm']);
    }

    public function testPKCS1Save(): void
    {
        $private = '-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=
-----END RSA PRIVATE KEY-----';
        $private = PublicKeyLoader::load($private)
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->withHash('sha256');
        $x509 = new X509($private->getPublicKey());
        $x509->addDNProp('id-at-organizationName', 'phpseclib demo cert');
        $private->sign($x509);
        $x509 = "$x509";

        $this->assertIsString($x509);

        $x509 = X509::load($x509)->toArray();
        $this->assertEquals('sha256WithRSAEncryption', $x509['tbsCertificate']['signature']['algorithm']);
        $this->assertInstanceOf(RSA::class, $x509['tbsCertificate']['subjectPublicKeyInfo']);
        $this->assertEquals('sha256WithRSAEncryption', $x509['signatureAlgorithm']['algorithm']);
    }

    public function testLongTagOnBadCert(): void
    {
        // the problem with this cert is that it'd cause an infinite loop
        $cert = '-----BEGIN CERTIFICATE-----
MIIBjDCCATGgAwIBAgIJAJSiNCIEEiyyMAoGCCqGSM49BAMCMA0xCzAJBgNVBAMM
AkNBMB4XDTE5MDUwOTAzMTUzMFoXDTE5MDYwODAzMTUzMFowDTELMAkGA1UEAwwC
Q0FNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUU4K0R0TDM0Syt0
RzZGR3o2QXJ2QzlySnlmN1Y5N09wY3ZWeG1IbjRXQStXc0E2L0dxLzZ1cUFBdG5Y
RDZOQUxsRVVSVFZCcmlvNjB4L0xZN1ZoTmx0UT09o1kwVzAgBgNVHQ4BAf8EFgQU
25GbjmtucxjEGkWrB2R6AB6/yrkwIgYDVR0jAQH/BBgwFoAU25GbjmtucxjEGkWr
B2R6AB6/yrkwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA6ZB6
+KlUM1ZXFrxtDxLWqp51myWDulWjnK6cl7b5AVgCIQCRdthTn8JlN5bRSnJ6qiCk
A9bhRA0cVk7bAEU2c44CYg==
-----END CERTIFICATE-----';
        $this->expectException(RuntimeException::class);
        $x509 = X509::load($cert)->toArray();
    }

    public function testLongTagOnBadCert2(): void
    {
        // the problem with this cert is that it'd cause an infinite loop
        $cert = '-----BEGIN CERTIFICATE-----
MIIBjDCCATGgAwIBAgIJAJSiNCIEEiyyMAoGCCqGSM49BAMCMA0xCzAJBgNVBAMM
AkNBMB4XDTE5MDUwOTAzMTUzMFoXDTE5MDYwODAzMTUzMFowDTELMAkGA1UEAwwC
Q0FNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUU4K0R0TDM0Syt0
RzZGR3o2QXJ2QzlySnlmN1Y5N09wY3ZWeG1IbjRXQStXc0E2L0dxLzZ1cUFBdG5Y
RDZOQUxsRVVSVFZCcmlvNjB4L0xZN1ZoTmx0UT09o1kwVzAgBgNVHQ4BAf8EFgQU
25GbjmtucxjEGkWrB2R6AB6/yrkwIgYDVR0jAQH/BBgwFoAU25GbjmtucxjEGkWr
B2R6AB6/yrkwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA6ZB6
+KlUM1ZXFrxtDxLWqp51myWDulWjnK6cl7b5AVgCIQCRdthTn8JlN5bRSnJ6qiCk
A9bhRA0cVk7bAEU2c44CYg==
-----END CERTIFICATE-----';

        ASN1::enableBlobsOnBadDecodes();

        $x509 = X509::load($cert);
        $this->assertInstanceOf(MalformedData::class, $x509['tbsCertificate']['subjectPublicKeyInfo']);

        ASN1::disableBlobsOnBadDecodes();
    }

    // from CVE-2024-27355
    public function testLongOID(): void
    {
        $cert = file_get_contents(__DIR__ . '/mal-cert-02.der');

        $x509 = X509::load($cert);
        $this->expectException(RuntimeException::class);
        $x509->toArray();
    }

    // from CVE-2024-27355
    public function testLongOID2(): void
    {
        $cert = file_get_contents(dirname(__FILE__) . '/mal-cert-02.der');

        ASN1::enableBlobsOnBadDecodes();

        $x509 = X509::load($cert);
        $this->assertInstanceOf(MalformedData::class, $x509['signatureAlgorithm']['algorithm']);

        ASN1::disableBlobsOnBadDecodes();
    }

    /**
     * @group github1387
     */
    public function testNameConstraintIP(): void
    {
        $x509 = X509::load('-----BEGIN CERTIFICATE-----
MIIGcDCCBVigAwIBAgIQRUgJC4ec7yFWcqzT3mwbWzANBgkqhkiG9w0BAQwFADB1MQswCQYDVQQG
EwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEoMCYGA1UEAwwfRUUgQ2Vy
dGlmaWNhdGlvbiBDZW50cmUgUm9vdCBDQTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlMCAXDTE1
MTIxNzEyMzg0M1oYDzIwMzAxMjE3MjM1OTU5WjBjMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMg
U2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxFzAVBgNVBAMM
DkVTVEVJRC1TSyAyMDE1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0oH61NDxbdW9
k8nLA1qGaL4B7vydod2Ewp/STBZB3wEtIJCLdkpEsS8pXfFiRqwDVsgGGbu+Q99trlb5LI7yi7rI
kRov5NftBdSNPSU5rAhYPQhvZZQgOwRaHa5Ey+BaLJHmLqYQS9hQvQsCYyws+xVvNFUpK0pGD64i
ycqdMuBl/nWq3fLuZppwBh0VFltm4nhr/1S0R9TRJpqFUGbGr4OK/DwebQ5PjhdS40gCUNwmC7fP
Q4vIH+x+TCk2aG+u3MoAz0IrpVWqiwzG/vxreuPPAkgXeFCeYf6fXLsGz4WivsZFbph2pMjELu6s
ltlBXfAG3fGv43t91VXicyzR/eT5dsB+zFsW1sHV+1ONPr+qzgDxCH2cmuqoZNfIIq+buob3eA8e
e+XpJKJQr+1qGrmhggjvAhc7m6cU4x/QfxwRYhIVNhJf+sKVThkQhbJ9XxuKk3c18wymwL1mpDD0
PIGJqlssMeiuJ4IzagFbgESGNDUd4icm0hQT8CmQeUm1GbWeBYseqPhMQX97QFBLXJLVy2SCyoAz
7Bq1qA43++EcibN+yBc1nQs2Zoq8ck9MK0bCxDMeUkQUz6VeQGp69ImOQrsw46qTz0mtdQrMSbnk
XCuLan5dPm284J9HmaqiYi6j6KLcZ2NkUnDQFesBVlMEm+fHa2iR6lnAFYZ06UECAwEAAaOCAgow
ggIGMB8GA1UdIwQYMBaAFBLyWj7qVhy/zQas8fElyalL1BSZMB0GA1UdDgQWBBSzq4i8mdVipIUq
CM20HXI7g3JHUTAOBgNVHQ8BAf8EBAMCAQYwdwYDVR0gBHAwbjAIBgYEAI96AQIwCQYHBACL7EAB
AjAwBgkrBgEEAc4fAQEwIzAhBggrBgEFBQcCARYVaHR0cHM6Ly93d3cuc2suZWUvQ1BTMAsGCSsG
AQQBzh8BAjALBgkrBgEEAc4fAQMwCwYJKwYBBAHOHwEEMBIGA1UdEwEB/wQIMAYBAf8CAQAwQQYD
VR0eBDowOKE2MASCAiIiMAqHCAAAAAAAAAAAMCKHIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAMCcGA1UdJQQgMB4GCCsGAQUFBwMJBggrBgEFBQcDAgYIKwYBBQUHAwQwfAYIKwYBBQUH
AQEEcDBuMCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcC5zay5lZS9DQTBKBggrBgEFBQcwAoY+aHR0
cDovL3d3dy5zay5lZS9jZXJ0cy9FRV9DZXJ0aWZpY2F0aW9uX0NlbnRyZV9Sb290X0NBLmRlci5j
cnQwPQYDVR0fBDYwNDAyoDCgLoYsaHR0cDovL3d3dy5zay5lZS9yZXBvc2l0b3J5L2NybHMvZWVj
Y3JjYS5jcmwwDQYJKoZIhvcNAQEMBQADggEBAHRWDGI3P00r2sOnlvLHKk9eE7X93eT+4e5TeaQs
OpE5zQRUTtshxN8Bnx2ToQ9rgi18q+MwXm2f0mrGakYYG0bix7ZgDQvCMD/kuRYmwLGdfsTXwh8K
uL6uSHF+U/ZTss6qG7mxCHG9YvebkN5Yj/rYRvZ9/uJ9rieByxw4wo7b19p22PXkAkXP5y3+qK/O
et98lqwI97kJhiS2zxFYRk+dXbazmoVHnozYKmsZaSUvoYNNH19tpS7BLdsgi9KpbvQLb5ywIMq9
ut3+b2Xvzq8yzmHMFtLIJ6Afu1jJpqD82BUAFcvi5vhnP8M7b974R18WCOpgNQvXDI+2/8ZINeU=
-----END CERTIFICATE-----');
        $x509 = X509::load("$x509");
        $this->assertSame($x509['tbsCertificate']['extensions'][5]['extnValue']['excludedSubtrees'][1]['base']['iPAddress'], ['0.0.0.0', '0.0.0.0']);
        $this->assertSame($x509->getExtension('id-ce-nameConstraints')['extnValue']['excludedSubtrees'][1]['base']['iPAddress'], ['0.0.0.0', '0.0.0.0']);
    }

    /**
     * @group github1456
     */
    public function testRandomString(): void
    {
        $a = 'da7e705569d4196cd49cf3b3d92cd435ca34ccbe';
        $a = pack('H*', $a);

        $this->expectException(RuntimeException::class);
        $x509 = X509::load($a)->toArray();
    }

    /**
     * @group github1542
     */
    public function testMultiCertPEM(): void
    {
        $a = '-----BEGIN CERTIFICATE-----
MIILODCCCSCgAwIBAgIQDh0LGipJ++wxFLj8X5MXKDANBgkqhkiG9w0BAQsFADCB
kDELMAkGA1UEBhMCVVMxDTALBgNVBAgTBFV0YWgxDTALBgNVBAcTBExlaGkxFzAV
BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
MS8wLQYDVQQDEyZEaWdpQ2VydCBWZXJpZmllZCBNYXJrIEludGVybWVkaWF0ZSBD
QTAeFw0yMDA3MzAwMDAwMDBaFw0yMTAxMjUxMjAwMDBaMIIBDjEdMBsGA1UEDxMU
UHJpdmF0ZSBPcmdhbml6YXRpb24xEzARBgsrBgEEAYI3PAIBAxMCVVMxGTAXBgsr
BgEEAYI3PAIBAhMIRGVsYXdhcmUxEDAOBgNVBAUTBzM2MzMwMTkxGTAXBgNVBAkT
EDEwMDAgVyBNYXVkZSBBdmUxDjAMBgNVBBETBTk0MDg1MQswCQYDVQQGEwJVUzET
MBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU3Vubnl2YWxlMR0wGwYDVQQK
ExRMaW5rZWRJbiBDb3Jwb3JhdGlvbjESMBAGCisGAQQBg55fAQMTAlVTMRcwFQYK
KwYBBAGDnl8BBBMHNTY3NTczOTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAOCl7WccAcvSaf5+pNsV82VjFuwdzEwjDYESZmIuurz95e+JtJZst/M3Hw90
YxKSDV4LdaVFAogXy2F+Npit1KhbBEb8vbBkm4LJ3iM8teE/10JugLyxrcVi3LSj
iKHs+rqxcTJsVYoR+CuPLuAbu4xKi+xQ4tVafrFd0Y21n6OL8nB2SRISHF58kRXq
UDW/NippF1AhcdCc5L5EmXFPCpyWfv+UXgTj9i+/I9AWUC3diHckb5NXd/wS7Jmq
5FE0uixRGTixI5a9uZr0jasTtfhlVtvqFyDmzARB/q9IU0eXm3dtcCJISIXGum6o
yCFUk8pyYsGd/M5Fyw7zbmEqsucCAwEAAaOCBgswggYHMB8GA1UdIwQYMBaAFOsN
zmX0UnV7TbPUsz0w41AYq+NuMB0GA1UdDgQWBBSkuL0+t0wu/+y2xkUY/FOSsiuV
ODAXBgNVHREEEDAOggxsaW5rZWRpbi5jb20wEwYDVR0lBAwwCgYIKwYBBQUHAx8w
gZkGA1UdHwSBkTCBjjBFoEOgQYY/aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
Z2lDZXJ0VmVyaWZpZWRNYXJrSW50ZXJtZWRpYXRlQ0EuY3JsMEWgQ6BBhj9odHRw
Oi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRWZXJpZmllZE1hcmtJbnRlcm1l
ZGlhdGVDQS5jcmwwUAYDVR0gBEkwRzA3BglghkgBhv1sCgEwKjAoBggrBgEFBQcC
ARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAMBgorBgEEAYOeXwEBMF4G
CCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL2NhY2VydHMuZGlnaWNl
cnQuY29tL0RpZ2lDZXJ0VmVyaWZpZWRNYXJrSW50ZXJtZWRpYXRlQ0EuY3J0MAwG
A1UdEwEB/wQCMAAwggOsBggrBgEFBQcBDASCA54wggOaooIDlqCCA5IwggOOMIID
ijCCA4YWDWltYWdlL3N2Zyt4bWwwIzAhMAkGBSsOAwIaBQAEFGckN8uhuoNkcXXh
wRAm7wkz4JRLMIIDThaCA0pkYXRhOmltYWdlL3N2Zyt4bWw7YmFzZTY0LEg0c0lB
QUFBQUFBQUNsMVR5MjdiTUJDODl5c0k5VXlhKytLanNITElJVWlCRnVqSjkxUlJR
cUdLSGNTQ25PYnJ1NVRVQkMwTVNKN2w3SEozZHJRL3o0OW03bC9PdytuWU51Q3dN
YTlQNC9IY05tV2Fuci9zZHBmTHhWM0luVjRlZCtpOTN5bS9NWmZoZmlwdEUySm9U
T21IeHpKdFlCNzZ5L1hwdFcyODhVWWpab24rdkR2M1AxNU9EOFBZdDgwMEhIL2I1
M056dForR2FleXZ2ZzNIWC8zOTErTit0K0w5ODkxVWpITEh0dm5zWTB6WFd1Ryti
YjVMQkJkek5vR2NSTHdGenk1NzdpeWk4eHlzUXdETDNnR2dnZWlZWTBYczJWQjJu
T0ZRODFQb0hBcVltaFBGUUhLRXVSTDBIdk5CbHhBTGgrQlNsazZwb0R3VXJnUU1i
R3QxcVVBazJwVjlBRS9PQitxc0k1S2xwUlN0cG5GSWxSSlo3RWVDZHZQVzdQNmQ5
T2JtWmgwVFdGd01ZakJrNXlHVnBFc0pNbU1BUjVHS1hmRmhPMzU3cWwwbnNFRGVl
Y29kQmcyVFZVblFjSFJBYkJBMHRDTGRpTDQ4OHRrdVVkZzRkbzF1SExzRlY0cjlD
Q3BsMXRJeDZKemVnMFZ4T2RGeUFTODhMMm03WU1sNnl1QkN5bVpycnNUb2N1YVpS
S094YUZhUXV5UTZGNXJ0cGI3UnUxd1N0SXdPcVV2NkZORjRWdFVqR1dGdEp2NUZn
S3p5d3d4TWprUnVXZFFBZEdEZEJqSjIzdXJGVEdvT0liU3FHRUZhNjc0RGJUQkg0
eTBuOVFBWjBqWHE2WVpDckhZNmlGYlI3cXYwa04rVi8zK0RIdXB2WFdLQXJNcWdF
YThWTXBXbytXRkdVcURPVWkxVXh3M3BJR20yUzZ4VXgyU0FlVUc2V2xGVDUvVnN0
S3FkVitlcWtwNHFTTHFnQlJTcmpnRzFTTlRCb0pETE10ZWpHTWEwT0hyNVg3Q3VZ
cXlPaC9WMFhwNjNJWUxTMTl4YUtlZGx0UHFsWDMzNkEwYlJhNW9nQkFBQTCBigYK
KwYBBAHWeQIEAgR8BHoAeAB2AFVZU64wlgCAbNLrUgimyZ6TGCisEFa0QhxVNhVM
X3WsAAABc6DTF3wAAAQDAEcwRQIgRsnN1miYsyCMT234C14MaMgSAgKHXmc7RrBM
a/1ovTMCIQCOc/THDvltzhZrtnoRSbjc2EYp57A0VVHvduQPa7FKBDANBgkqhkiG
9w0BAQsFAAOCAgEA8UQt5jcUeOaDkhvbLq380Oq1Jy8Vr1BO1GPisn20KRCz/NvE
56f8hhmZlZ1xXfOM+JCaGQnwVwcRBQtLQ/+6bmeT8/WM3hf9A5rP0g0ZxvaAlQtu
e6UjvgnNx02QOKNPrmxN0rW8s24kUi0OAf1ump3SY5Ab+S+ywRG7Ah+3qch+FwA8
CYau9TgV5kvfYDRULBM84EeFhsPcwT+YJ5u7RvkGQobqNao21Ti5tupiks/9NzI8
splBS77Z6bPdFGvZ7pJdXiiDB2+SZdyv8iqDFM6mKRbOcuwAHcTY2zVhcS46H7SO
8OU7L/2y0XQB1rMtQDarCKwdAcsAb2e+N8mYQ0glQX4k41Sf4saMXsU1EjnOCUas
YxvVgJRD+fe4JWf8EO59fElzkrQsT3guBIzV5Kg1dYaCHngCYQIakjKQM0eKxZ3d
vn4648A0vXynhJUThOSxN4jbvVA5uYYHqHDMjJtkBPDA7HtLSIxRNattshOAoeC5
LMszAsL9th/WoXkAa2lTs2kashOHEpx+ncGactrL8tu7dvU01Yk6yP1QAjFEo1Nt
8umUG7jQQIuquB2ry4qzFuQvKpbNQZ//9RsSmq1nni+DEKd/S63N7T8M0FpioLVm
Z2OXFTCG5ORjPUOyMGjxzjEPZWmTOG+gqNOc0HKXbuBAsGZbK4dind+YdZE=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIHLzCCBRegAwIBAgIQDZXVhKBTvJ0ZjW6meNxHhTANBgkqhkiG9w0BAQsFADCB
iDELMAkGA1UEBhMCVVMxDTALBgNVBAgTBFV0YWgxDTALBgNVBAcTBExlaGkxFzAV
BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
MScwJQYDVQQDEx5EaWdpQ2VydCBWZXJpZmllZCBNYXJrIFJvb3QgQ0EwHhcNMTkw
OTIzMTIyNTQyWhcNMzQwOTIzMTIyNTQyWjCBkDELMAkGA1UEBhMCVVMxDTALBgNV
BAgTBFV0YWgxDTALBgNVBAcTBExlaGkxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMS8wLQYDVQQDEyZEaWdpQ2VydCBW
ZXJpZmllZCBNYXJrIEludGVybWVkaWF0ZSBDQTCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBAPfhMd+2RBjNZpqq0GVUF0kKK72fQxhJbnxgYv7GFpmi69sX
dgeqH9RE07ShTDtkLks9G/GuiXsLEmjSCBDDTwfB3hpbdrZsNQFWOIRHXmU8ykuP
bCd/HVRZGULeWvbt93deEB1el5MpxP9Fs3LKjw7xytbuM/nkGJ4D2R1IHC953FoU
4BYsp+8VB1+7Gh8eKVh+HpmBeEfIB+cuq4FpZKxi+F5J7UjW5yO4SuDcTF4AMY0J
DPuKIy+Og6laNOtDS30P1CUu1N6BwLMYTbeqyYHJ7B3kLWsDceGMqIcxo8zrk1rT
sJctcXHXhB4k2PnVxt8qkQjg2Lo++kU0dFSUyrzvg3WrGypv9vphWMI+vmCjmu2K
0BZLZ4nKshoTX495R6pGbsecGaaGgACB/1NcGI7PVp7spY2ytLvHHZ+Hh446BGFy
AdM8lZCMXEhNftP8RRRVr8mwHHzyIa86r4yk0SkOlXUkNrGdTqqyMSDJ3W7DWGO/
vCObzXiM0aq77ebD/0fE5LsZhEJYx7txF9NA1DoICgHp8zqF35i3UOp4+5IyJ8A9
MjqYcX+LayH06B45bMgTHLmJKcsRYvXAtu+nIvIL0fk4+Ea7kJ7MNx5/udS89b2f
vSFC4hmA3OBDiJqGmldwqJL/HP7RI8O54yj10vpiH4obDo8QgfhKSVoX5HwDAgMB
AAGjggGJMIIBhTAdBgNVHQ4EFgQU6w3OZfRSdXtNs9SzPTDjUBir424wHwYDVR0j
BBgwFoAU7G8ipLME4sFjh+Z3Y+pGaU7u/OswDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
JQQMMAoGCCsGAQUFBwMfMBIGA1UdEwEB/wQIMAYBAf8CAQAwfAYIKwYBBQUHAQEE
cDBuMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRgYIKwYB
BQUHMAKGOmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFZlcmlm
aWVkTWFya1Jvb3RDQS5jcnQwSAYDVR0fBEEwPzA9oDugOYY3aHR0cDovL2NybDMu
ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VmVyaWZpZWRNYXJrUm9vdENBLmNybDBCBgNV
HSAEOzA5MDcGCWCGSAGG/WwKATAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5k
aWdpY2VydC5jb20vQ1BTMA0GCSqGSIb3DQEBCwUAA4ICAQA6v371ixHAA9WyGlFr
+RvmmqkZZg9pf6+j5sKImeTFAHfYz3TJa2wmDRpZxSRYy9VUFOMPVDEavsJ2i5Ua
jEpkJ/7VHbX60joKBxQHKCbMpbwGen6pTXRaeE6CET2zCMbyiIqT2E6OiBZL8cWT
sgLbdhVKspoOi+c3JwTR4khR24J9IQVxK90Nq3zeciYgBvM3G+ZJtZgkA58CRdex
xVO6O57bwe4ti4rlRgWOGgAFpFrJSD1jqhhHD3MWg17NI4k0ciBPoDHHBAI8hiqg
jPM+y6aEGww7BFSfkp5tl/Aq9uGXCwxNLOc3UlUd8Cc0qH1KfkvjrumVMmJhsk9I
88YefbCuGPZ5Q8V2LIz7LrNDh0VRq/HSENXn1sBGlAFahgUTk/cWJ8nKA+8mHMlE
NGmx205Rtbf9lVL1CbH3QFwlvGEfqoMXw6G9JW2hFQVTKpBKuzjQw43CEw12lstP
oa96ixNAXXVGJsdKpYCqTIWJ0x1DssvG2shvzdHxawvYQ3C+/jaEoQ6bxSIdanI2
NMtBdy9Q0TjDc7uf/eaUYKkP4wskNc1Os23oHllFHVm++8wdDltNulc7B1TXIQ+2
oD5EoULMFSVUHX8gtyd463GgOQtBDwf3aZ4Xe6eDrhdfI/4IW098kVcg+qFO841L
qzFkAKWjJj4KjfrbZX4C0Spfxw==
-----END CERTIFICATE-----';

        $x509 = X509::load($a)->toArray();

        $this->assertIsArray($x509);
    }

    /**
     * @group github1586
     */
    public function testComputeKeyIdentifier(): void
    {
        $key = RSA::createKey(512);
        $x509 = new X509($key->getPublicKey());
        $id = $x509->createSubjectKeyIdentifier();

        $this->assertIsString($id);
        $this->assertIsString((string) $x509->getExtension('id-ce-subjectKeyIdentifier')['extnValue']);
    }

    /**
     * @group github1665
     */
    public function testImplicitV1(): void
    {
        $x509 = X509::load('-----BEGIN CERTIFICATE-----
MIIDZDCCAkwCCQDIda+OHQTFSTANBgkqhkiG9w0BAQsFADB0MQswCQYDVQQGEwJE
RTEMMAoGA1UECAwDc2RmMQ4wDAYDVQQHDAVzZ3J3ZTEOMAwGA1UECgwFZXJncmUx
DDAKBgNVBAsMA2VyZzEMMAoGA1UEAwwDd3JnMRswGQYJKoZIhvcNAQkBFgxqYWRm
c0BzZGYuZGUwHhcNMjEwNTI2MTIxMTQwWhcNMjIwNTI2MTIxMTQwWjB0MQswCQYD
VQQGEwJERTEMMAoGA1UECAwDc2RmMQ4wDAYDVQQHDAVzZ3J3ZTEOMAwGA1UECgwF
ZXJncmUxDDAKBgNVBAsMA2VyZzEMMAoGA1UEAwwDd3JnMRswGQYJKoZIhvcNAQkB
FgxqYWRmc0BzZGYuZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCy
Cdw2oh1mLuMq9icQWkv1Sgt1p4RhwAeiYcqo/lm0VAf3LjPDDCccXmwFUEQJ2g8r
UPmvazT0IaYytsPGlNCS2nA+OyY/NBySpBcksiQHEfmrW04/jsoJ2oql+BCWkGsF
dAewCWpzvL8RZxoKYlZwBfvyDn4QFn1TsuCxnHdKvrcpvzaQcfBcJT8P39TFTlUc
mBoa3Y/iIULlvwk3w+1LjY7gnNDqNyGaOSZpfpliTxwvIK/PJbStD0srT+voSPZW
4Xt1oOxqmdFvTL+6H6xT/HrEfwtN/+bU1ZmY23Kcq21sczy4dvglrnPqmRUVjoL8
qs/qT8GNZmvZxB5dLXbfAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAH5ciSY+dD+H
CmnMHmZwyE1q3QifO/qiygNeosnth6dYI+JxR9aAJKB6vnBQl3IReeoniaSH/iaH
DthLeo0haSb5d3P911wPmw3gut7ungnQ1X/HHroDL6UASj+x2Dux04w7Q3YNyqGT
OObFmWs68kxLV3V0TDYNjz+nU4wVqFDKlehdoDm4Q/uq2FIRbU/qWS61sxI/s+Pg
42cGvzZe673OZgtOIDuRo/8Ahe/Vc285nbuMRMTWIs9e5fGSW8b6gVmKhBUmIFGj
bMgrc775Q3t4hkitEymosEiqHsj7YM6EpgHZwke+CNdybIUw+u9L3xxOl4mEeY6l
itRo91vT68U=
-----END CERTIFICATE-----');
        $this->assertEquals($x509['tbsCertificate']['version'], 'v1');
    }

    /**
     * @group github1657
     */
    public function signWithEncryptedPSS(): void
    {
        $private = PublicKeyLoader::load('-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIpZHwLtkYRb4CAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBCCGsoP7F4bd8O5I1poTn8PBIIB
YBtM1tgqsAQgbSZT0475aHufzFuJuPWOYqiHag8OUKMeZuxVHndElipEY2V5lS9m
wddwtWaGuYD/Swcdt0Xht8U8BF0SjSyzQ4YtRsG9CmEHYhWmQ5AqK1W3mDUApO38
Cm5L1HrHV4YJnYmmK9jgq+iWlLFDmB8s4TA6kMPWbCENlpr1kEXz4hLwY3ylH8XW
I65WX2jGSn61jayCwpf1HPFBPDUaS5s3f92aKjk0AE8htsDBBiCVS3Yjq4QSbhfz
uNIZ1TooXT9Xn+EJC0yjVnlTHZMfqrcA3OmVSi4kftugjAax4Z2qDqO+onkgeJAw
P75scMcwH0SQUdrNrejgfIzJFWzcH9xWwKhOT9s9hLx2OfPlMtDDSJVRspqwwQrF
QwinX0cR9Hx84rSMrFndxZi52o9EOLJ7cithncoW1KOAf7lIJIUzP0oIKkskAndQ
o2UiZsxgoMYuq02T07DOknc=
-----END ENCRYPTED PRIVATE KEY-----', 'demo');

        $subject = new X509($private->getPublicKey());
        $subject->addDNProp('id-at-organizationName', 'phpseclib demo cert');
        $private->sign($subject);

        $this->assertIsString("$subject");
    }

    /**
     * @group github1676
     */
    public function testMalformedExt(): void
    {
        $a = '-----BEGIN CERTIFICATE-----
MIIDtjCCAmmgAwIBAgIUOynecffcNv1/7oqCfu98x899PhwwQgYJKoZIhvcNAQEK
MDWgDTALBglghkgBZQMEAgGhGjAYBgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIBogMC
ASCjAwIBATAcMRowGAYDVQQKDBFwaHBzZWNsaWIgQ0EgY2VydDAeFw0yMTA2MjUw
MTQ1MjlaFw0yMjA2MjUwMTQ1MjlaMBwxGjAYBgNVBAoMEXBocHNlY2xpYiBDQSBj
ZXJ0MIIBVzBCBgkqhkiG9w0BAQowNaANMAsGCWCGSAFlAwQCAaEaMBgGCSqGSIb3
DQEBCDALBglghkgBZQMEAgGiAwIBIKMDAgEBA4IBDwAwggEKAoIBAQCm8w3WEr4t
rbTaAHLI4uAGkZ5mJG8tgThw/qlADPZODjyJtNBZ1i39URXkHa4jdTfLMaCg8aWp
6eouRnNftUktmM4lG3j1JF6Cq2SkF93zJ2RZq3Ldpnv1jXS9qmtsndSzElria6f7
qY3c63S0YFYvNLmMd5lECPYuS3fj0DcPp1Gyy1GnfjSu6OyP34gtjOpZ3bSQmpTg
78HllRZiq6vQIAw6Svoi4Ih573PGRjVHbh/KP5/4gP0ClW+qGjR+qJinmBSOISRU
RSP3Yqh1eSo/gdqOfe+8g7ffTdsZ77xzP2nwq9wsmSyFh/jbQyG05R1cC0zGfBdo
3sDkSw5KDMQzAgMBAAGjUTBPMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBTsxDp1d394JKfAJZOuA9YQSvtvWjAQBggrBgEFBQcBAQEB/wQB
ADBCBgkqhkiG9w0BAQowNaANMAsGCWCGSAFlAwQCAaEaMBgGCSqGSIb3DQEBCDAL
BglghkgBZQMEAgGiAwIBIKMDAgEBA4IBAQCF8DNkkP5z2mkHoo0SvoUpscbaSpXF
jjMpLsQwdhar1jbrEIEQpSGsZlmxpGroBj91wQLjJv7godfFC6b2T4cRcj5NZAEI
ZyoxrfZ0WU609ZAKFooYwEA2nLAG8Y4ygD5adT45MhmqKs79p4uaG5Z78zQrkUYY
d9BtBm0pyZ513s+KW/keUxVKlHnnxdV9FIis0S/d74mjass4YjPZcWnss6TBfIyD
EbQ5UK6Zu74q0lQLp7t14zSQ2B5tclVnM7jY0RiRzpLgDCq3kpbaw6KvFzH9lfPP
BbNA6tFZAwLoX18R6yEmzHAQ+R2Eliiaz7mgQ+M2d0ec6qQJFoO7aJsX
-----END CERTIFICATE-----';

        $x509 = X509::load($a)->toArray();

        $this->assertIsArray($x509);
    }

    public function testWildcardCert(): void
    {
        $cert = '-----BEGIN CERTIFICATE-----
MIIKqDCCCZCgAwIBAgIQAZ3dCTUFVNcaZ4TM/m6DFTANBgkqhkiG9w0BAQsFADBY
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEuMCwGA1UE
AxMlR2xvYmFsU2lnbiBBdGxhcyBSMyBEViBUTFMgQ0EgMjAyMyBRMzAeFw0yMzA5
MTIxOTM4MDVaFw0yNDEwMTMxOTM4MDRaMBIxEDAOBgNVBAMMB2Nubi5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDsZniL9RpV7hDYPJvS4TGa39w5
BLHGsPhi4lV4HVtyIme0/NMMmszIeNoY+aaDSM2dn0gw29GIq1prZSAQK8BgDU6a
otU5mWG8J+xABnn75DQ1BHjXZFl4EfjL4mIhMaVY34O+0wG06owvFDUgxRzYnwlb
y6WEJfTRyv70MF6EIq0zZxW2cMgfyuq8ZEtgYddSr4I/2/xVxACBUDFYNqYbr9AR
qmJKvzglrSYULaBJ84oY3RnBnDCVUkMW3qYT1mIDop+Jz4wLyMyvHq0QA0wY/BhI
ByhJTkdQy7xH2N8O2MohQmaVo6x6w01cqsZyIHND1JSL3lAJiMtU8aMl3+edAgMB
AAGjggeyMIIHrjCCBGcGA1UdEQSCBF4wggRaggdjbm4uY29tgg0qLmFwaS5jbm4u
Y29tggwqLmFwaS5jbm4uaW+CHSouYXBpLmVsZWN0aW9udHJhY2tlci5jbm4uY29t
ghYqLmFwaS5wbGF0Zm9ybS5jbm4uY29tghAqLmFyYWJpYy5jbm4uY29tghQqLmFy
dGVtaXMudHVybmVyLmNvbYIPKi5ibG9ncy5jbm4uY29tghgqLmNsaWVudC5hcHBs
ZXR2LmNubi5jb22CCSouY25uLmNvbYIIKi5jbm4uaW+CDyouY25uYXJhYmljLmNv
bYIOKi5jbm5tb25leS5jb22CESouY25ucG9saXRpY3MuY29tghYqLmNvbmZpZy5v
dXR0dXJuZXIuY29tghEqLmRhdGEuYXBpLmNubi5pb4IRKi5lZGl0aW9uLmNubi5j
b22CFyouZWRpdGlvbi5pLmNkbi5jbm4uY29tghwqLmVkaXRpb24uc3RhZ2UubmV4
dC5jbm4uY29tgh0qLmVkaXRpb24uc3RhZ2UyLm5leHQuY25uLmNvbYIdKi5lZGl0
aW9uLnN0YWdlMy5uZXh0LmNubi5jb22CEyouZWxlY3Rpb25zLmNubi5jb22CGSou
ZWxlY3Rpb250cmFja2VyLmNubi5jb22CDCouZ28uY25uLmNvbYIPKi5pLmNkbi5j
bm4uY29tghYqLm1hcmtldHMubW9uZXkuY25uLmlvgg8qLm1vbmV5LmNubi5jb22C
DioubmV4dC5jbm4uY29tghYqLm9kbS5wbGF0Zm9ybS5jbm4uY29tgg8qLm91dHR1
cm5lci5jb22CEioucGxhdGZvcm0uY25uLmNvbYIfKi5zZWN0aW9uLWNvbnRlbnQu
bW9uZXkuY25uLmNvbYIUKi5zdGFnZS5uZXh0LmNubi5jb22CFSouc3RhZ2UyLm5l
eHQuY25uLmNvbYIVKi5zdGFnZTMubmV4dC5jbm4uY29tghEqLnN0ZWxsYXIuY25u
LmNvbYIUKi50ZXJyYS5uZXh0LmNubi5jb22CECoudHJhdmVsLmNubi5jb22CEyou
d3d3LmkuY2RuLmNubi5jb22CD2FwaS5ldHAuY25uLmNvbYIWY2xpZW50LmFwcGxl
dHYuY25uLmNvbYINY25uYXJhYmljLmNvbYIMY25ubW9uZXkuY29tgg9jbm5wb2xp
dGljcy5jb22CDWRjZmFuZG9tZS5jb22CHGdyYXBocWwudmVydGljYWxzLmFwaS5j
bm4uaW+CFGkuY2RuLnRyYXZlbC5jbm4uY29tghlwcmV2aWV3LmRldi5tb25leS5j
bm4uY29tghhwcmV2aWV3LnFhLm1vbmV5LmNubi5jb22CGXByZXZpZXcucmVmLm1v
bmV5LmNubi5jb22CG3ByZXZpZXcudHJhaW4ubW9uZXkuY25uLmNvbYIacHJldmll
dzIucmVmLm1vbmV5LmNubi5jb22CD3VuZGVyc2NvcmVkLmNvbTAOBgNVHQ8BAf8E
BAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBT9
Fy8eFhWRk9UjmQVNdVD8lZEhFTBXBgNVHSAEUDBOMAgGBmeBDAECATBCBgorBgEE
AaAyCgEDMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29t
L3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZ4GCCsGAQUFBwEBBIGRMIGOMEAG
CCsGAQUFBzABhjRodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9nc2F0bGFz
cjNkdnRsc2NhMjAyM3EzMEoGCCsGAQUFBzAChj5odHRwOi8vc2VjdXJlLmdsb2Jh
bHNpZ24uY29tL2NhY2VydC9nc2F0bGFzcjNkdnRsc2NhMjAyM3EzLmNydDAfBgNV
HSMEGDAWgBTtoOYBBT40ghqkT1/FvRFBqt/zYTBIBgNVHR8EQTA/MD2gO6A5hjdo
dHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2NhL2dzYXRsYXNyM2R2dGxzY2EyMDIz
cTMuY3JsMIIBfgYKKwYBBAHWeQIEAgSCAW4EggFqAWgAdQDuzdBk1dsazsVct520
zROiModGfLzs3sNRSFlGcR+1mwAAAYqK5qvdAAAEAwBGMEQCIE08u4H1qqO/W1OP
YxuxGftmdYvpngZDDBIKPJtwCB1qAiBjpQIgGnsX7H5wVWzxZtpff+gB6a9V+VGx
YY6hTg5eSAB2AD8XS0/XIkdYlB1lHIS+DRLtkDd/H4Vq68G/KIXs+GRuAAABiorm
rCoAAAQDAEcwRQIhAKgfE42oSB7890qz2OJXfydLzubHcsHtPNbO43Z3IsczAiBX
bvuajpVoxMlYmMHhiVS4/qF9Wd1nACXQBy3KaTen8AB3AHb/iD8KtvuVUcJhzPWH
ujS0pM27KdxoQgqf5mdMWjp0AAABiormrGkAAAQDAEgwRgIhAOCBs1ExXErb1s3+
mI53aclpYutFJSWHmbnxbw5lULlEAiEAsrJQzWT2E4w5xcoeC0Zt+nMubTJG2BG7
2KKQnHPiNlswDQYJKoZIhvcNAQELBQADggEBAGMUNah4Pw60DYWQbtlH0jFYdvNM
s+Vsh27OQEYbhE2itGWs0JvvQUDst7Y+jMHPre5NZtdmr1RnmQFoVofTvwxQxtJ4
VOqJfh2X1LTv4VrZI9m6lBLN729CDO/TKeVP9hiflVqe7faAXT8KBEFwPWE5If+z
VqSx3vPmDx+RM7OXYrVzhEmhVVjRq7yANUF+oxW64zK4zsNzYGUAyp1gmInaXKN5
XSRklj10ZrVHcd0XLuAME/9+54Bm7TvRfI46hfCfu6FbQPIX3gg+5j+MZJSdIuQJ
dzXhMVAQYlpu27381/Ts2SuDx6v/cZ8lV8D5o/xTtCpWAnLxM2bxSyVnYbk=
-----END CERTIFICATE-----';

        $x509 = X509::load($cert);

        $this->assertTrue($x509->validateURL('https://asdf.cnn.com/'));
        $this->assertFalse($x509->validateURL('https://asdf.cnn2.com/'));
    }

    /**
     * @group github1943
     */
    public function testWeirdCharsCert(): void
    {
        $cert = '-----BEGIN CERTIFICATE-----
MIIDtTCCAp2gAwIBAgICECEwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMx
ITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28g
RGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNjAyMDcx
NzI0MDBaFw0yNDAxMDYwNjQ0NThaMHkxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJD
QTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEUMBIGA1UEChMLR29vZ2xlIEluYy4x
GDAWBgNVBAsTD0dvb2dsZSBSZXNlYXJjaDEVMBMGA1UEAxQMKi5nb29nbGUuY29t
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAxUWTaM/RKjoA8urhPYXr
Nh2Oz9HA88XkFIxhD3pm80wBlTTTnymSJJVWKpEJO7OyengVFRIv7U19VAFd8VCh
TCiFl7a4hsiWWQi3zh/NYgj0BnweNriblknBKTze6te1DP8otZ22qBUmhCR27aER
MWE9urWLwMIuJN/hxK234MljS9lBB3fv52RrZzSftga/P5zK34ZOlbnGcLbtoKR3
p0uWakBZM8u/665hQ4u4+YkA2kJy5YSF6wXpYKl29/mj1w9ODJTUFj3KmliiGXeo
2IhYLu4Pq52D7OKjDvKZRKK6tOM8Pii1c310ljlCewCuF/Oy/ygbNmaJG7J8/jTA
pwIBA6NfMF0wDAYDVR0TAQH/BAIwADANBgNVHREEBjAEggJhKzAdBgNVHQ4EFgQU
Zd/yRfldVXIxnAKzGaO6vZrb2XswHwYDVR0jBBgwFoAU4J1tAjJyIZ/+BvOatp4W
N1Fo5MMwDQYJKoZIhvcNAQELBQADggEBAAcwSIxKQegRqCs7adDb3VbqP1Ld0dA6
FydwendbN1P4NaqqdM89NhpOVZ5g60eM4sc08m5oZIMWqjwp3Gyf2pqM2FMQ02zi
1lMRb+t9rtjtZXCdcTjuwySYXw7M7NM0Lxhv7yN9+Vben1RTBWFghk8y4t6sai5L
68hFu+fkQzKIpHE/9cdBS+rtqyCrNit3kvqVhVpGECTS2flTBHnCe7mINojSTOsB
JYhGgW6KsKViE0hzQB8dSAcNcfwQPSKzOd02crXdJ7uYvZZK9prN83Oe1iDaizeA
1ntA2AzsC0OGg/ekAnAlxia3mzcJv0PgxRpSG7xjWSL+FVFTTs2I/wk=
-----END CERTIFICATE-----';

        $x509 = X509::load($cert);

        $this->assertFalse($x509->validateURL('https://aa'));
    }

    // from CVE-2024-27354
    public function testLargeInteger(): void
    {
        // cert has an elliptic curve public key with a specified curve (vs a named curve) with
        // an excessively large integer value
        $cert = file_get_contents(__DIR__ . '/mal-cert-01.der');

        $x509 = X509::load($cert);
        $this->expectException(RuntimeException::class);
        $x509->getPublicKey();
    }

    // from CVE-2024-27354
    public function testLargeInteger2(): void
    {
        // cert has an elliptic curve public key with a specified curve (vs a named curve) with
        // an excessively large integer value
        $cert = file_get_contents(__DIR__ . '/mal-cert-01.der');

        ASN1::enableBlobsOnBadDecodes();
        $x509 = X509::load($cert)->toArray();
        $this->assertInstanceOf(Element::class, $x509['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['parameters']);
        ASN1::disableBlobsOnBadDecodes();
    }

    /**
     * @group github2051
     */
    public function testRSACertWithECSDASig()
    {
        // a secp256r1 key
        $CAPrivKey = PublicKeyLoader::load('-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYZs/Y9XurjuN8SQ5
7Fyy1mTgHjFsdt0/3mOH7pfUbh6hRANCAASnmS1cmSu9dHOYrBg9aJRBs3PLPK62
u0s8T1gmnGIpKMyrHC3Sh6V2UczDODqpMXYiAsP6iPhiaq/3MmuhA0UA
-----END PRIVATE KEY-----');
        $CAPubKey = $CAPrivKey->getPublicKey();

        $ca = new X509($CAPubKey);
        $ca->addDNProp('id-at-organizationName', 'phpseclib CA cert');
        $ca->setEndDate('lifetime');
        $ca->makeCA();
        $CAPrivKey->sign($ca);

        // a 2048-bit private key
        $privKey = PublicKeyLoader::load('-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDCgThSXWv0segP
h6PkuQOp8Hl7vB/M6KBrpY+igKOG5IbXO6Fkhw/1nmgswa4tUu9b8Co9/HPDX/0X
owHoZuriLQluPdFAl9TJsiL4Etjui/vCzmvtAHlC6N8MjhpXJj/1gdX3sEwhTfnw
zAqQrR7SxIcoX4zHxHfQxsbR9my6x4HYSKVOEmJtDcTenaDXVqrHfzsc7FIAouSd
UL2TxrgalyrKZce50iF/1SoXLvD0XxXgJZhVkMzcsycNMf4a5+xDQOaAl31DeSYT
/x2CamRVBE3F+Tg1cegXBm6Dxhl5+TXgAhduFlBqlp8BMGlpE2lDdNpBYbDKGJs7
LMdV+pN7AgMBAAECggEADHgvTax6ks3jBDfcbHnl/7uQdjvJyB+zxSLwkejwUuIM
uPi0MJcuET+OCyyBh5tVCA5eDupD26coOR80rJsIfOaJP72L0DnLpQCcGE5RBP4J
zmRAbAnHPGBkiFAF5Udo+0rPFlmBj/MJToQuOzc2DioWRiLWCiqQydwse+Jx9wld
rJQ5WJfDGWV1T4nm88uzCDoMST6/7drwXNtyAEUHglcxnTj76t5AJ9YfI6FTiK64
8tTjBr2f7D0uTsCw7ueDynNTTwGIvyH1UaLTfrdTq/Cfki8ztyCvPgBItgVlgAD5
s85XXE4hqWKRgxJTG0OExyxeSLMpvbsVU/60Y/PcuQKBgQDlr2x77yuz3tIkXO+j
50exlhCH5/iuAQ9vw8QUQlde63B86U9/Y8SYS0kd1CdmHPNaeve4frmleY1iWAfC
AUAUaccKONlNbcVgcBzv7HXK+QmhRCb7EGGKFeb1O3oc1t8F1FRCa3hCtPchAVbu
PGIL6E3VwO36XYDXfS+jAZVIQwKBgQDYyfd+WYCM6YixDKZAGgfLSU/1sdt4lDGe
elObx0XeO+8kylqbk41WI92a4pQRnpZgHiyx48dsfa0vEO0zkGmfANxO/g6RxUTZ
zW3qGj8njhtsY6ymmHj+Ncu9/lnY6EpfCVSelxsVz+5XufjZfWNHj8mdEWDzFkuZ
BmcjQPlQaQKBgQDHfv3wC4Xe/ktx8BLpPuojkh8bnF1/7UXWIqh9nD29ISwcIp29
HQ/V45ZHRU1PQRgR37qoUdG3q4MlByb92A4rbNDHzSbZPN3x7I8FyVFqkbJOkx50
dP7zbCClohpnUC54Jrtk0WmsLvhzf3FdDa9vfj+UyLUq/+n3wTEOGULrdwKBgAGT
FfUY+VIMsC15BgwZJE1Zrvb937Y0fVfFU64h+GPw03/U6GuQ2snxYL6rPqASIs13
6qMwIFatYwCggtiJB/tbqj34omp0oFdkopO8tRC4e4KCBtL+8IIIKf6rRkPJDCE8
lBzCxDOYWwbQFvqdaocuiCxX3/hkBRCLd1xOMIFhAoGAanaZkg7wogxseU0CDQWr
ek+8xhvMsVmSs20JhR0WWUxNxZblKCJOMTzDnNxTajl8OeGfHLJER20aubB08/Fh
3XTCUzLk69tfwhvGTVorZ+bQTAM1X18nzD89J03g/IaHxxR/nyB39Yq8yqNvuP0D
Zf+6b317dHQhk60gz+CIt8s=
-----END PRIVATE KEY-----');
        $privKey = $privKey->withPadding(RSA::SIGNATURE_PKCS1);
        $pubKey = $privKey->getPublicKey();

        $cert = new X509($pubKey);
        $cert->addDomains('whatever.com');
        $cert->setEndDate('lifetime');
        $CAPrivKey->sign($cert);

        $cert = $cert->toArray();

        $this->assertFalse(isset($cert['signatureAlgorithm']['parameters']));
        $this->assertFalse(isset($cert['tbsCertificate']['signature']['parameters']));
    }

    /**
     * @group github1027
     */
    public function testInfiniteLoop(): void
    {
        $cert = '-----BEGIN CERTIFICATE-----
MIIGzTCCBbegAwIBAgIIIBEEIJIEBAEwCwYJKoZIhvcNAQELMHUxCzAJBgNVBAYT
AlJPMR0wGwYDVQQKDBRDZW50cnVsIGRlIENhbGN1bCBTQTEUMBIGA1UECwwLQ2Vy
dERpZ2l0YWwxMTAvBgNVBAMMKENlcnREaWdpdGFsIE5vblJlcHVkaWF0aW9uIENB
IENsYXNzIDQgRzIwHhcNMTYwNjA5MjEwMzA5WhcNMTcwNjA5MjEwMzA5WjBwMQsw
CQYDVQQGEwJSTzEdMBsGA1UECgwUQ2VudHJ1bCBkZSBDYWxjdWwgU0ExFDASBgNV
BAsMC0NlcnREaWdpdGFsMSwwKgYDVQQDDCNDZXJ0RGlnaXRhbCBWYWxpZGF0aW9u
IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALx1
4gvGI0v0i01Fqtp9ZlNhh+jSInff9Pjh2G9gJ9/M2gRO3FXSv4g9swuw4I/0rphX
CdeQBdKYAintKBSsP6pUHS0TokSVhhj8zFiYPrusPTmMq5FprY8iWn0Fr2daLGxB
QS8Q6vCu30rczLFL2XqZBmHvMJTAe+o95Y+M3NVY7V5KQ+Jhy/1u5lTiOlDnV72a
GK05Mre2EWdAS/a1P6mnsTPV1oTPJb4yH/GUD/Qi9Zzz3ZUUcDbXwHH0GEqsWJyu
A8RpieqfpkZl2Z3kt8KTYoTLwqVg+pGPzmKHxWbBbtCNVPpctvwheLBfNeGR85gn
/u9NsCmOBOk2OZf1Fq8CAwCxY6OCA2gwggNkMIGIBggrBgEFBQcBAQR8MHowOgYI
KwYBBQUHMAGGLmh0dHA6Ly9ub25yZXB1ZGlhdGlvbmcyLmNlcnRkaWdpdGFsLnJv
L2NhL29jc3AwPAYIKwYBBQUHMAKGMGh0dHA6Ly9jZXJ0cy5jZXJ0ZGlnaXRhbC5y
by9ub25yZXB1ZGlhdGlvbmcyLmNydDCBswYDVR0jBIGrMIGogCD2bp4Ayiw1n6YC
yyc9vduqYmeMvt/20TXxx8DNzt/FJaF8pHoweDELMAkGA1UEBhMCUk8xHTAbBgNV
BAoMFENlbnRydWwgZGUgQ2FsY3VsIFNBMRQwEgYDVQQLDAtDZXJ0RGlnaXRhbDE0
MDIGA1UEAwwrQ2VydERpZ2l0YWwgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
eSBHMoIGIBEEIJICMCkGA1UdDgQiBCAsUTcCCeWYU5wAXqO974X+iESFznjE5bvY
3/B8dozrvjCBjAYDVR0gBIGEMIGBMEEGCysGAQQBgvYaAQEEMDIwMAYIKwYBBQUH
AgEWJGh0dHA6Ly93d3cuY2VydGRpZ2l0YWwucm8vcmVwb3NpdG9yeTA8BgZngQwB
AgIwMjAwBggrBgEFBQcCARYkaHR0cDovL3d3dy5jZXJ0ZGlnaXRhbC5yby9yZXBv
c2l0b3J5MIHZBgNVHR8EgdEwgc4wgcuggciggcWGLmh0dHA6Ly9jcmwuY2VydGRp
Z2l0YWwucm8vbm9ucmVwdWRpYXRpb25nMi5jcmyGgZJsZGFwOi8vbGRhcC5jZXJ0
ZGlnaXRhbC5yby9jbj1DZXJ0RGlnaXRhbCBOb25SZXB1ZGlhdGlvbiBDQSBDbGFz
cyAzIEcyLG91PUNlcnREaWdpdGFsLG89Q2VudHJ1bCBkZSBDYWxjdWwgU0EsYz1S
Tz9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0O2JpbmFyeTBHBgNVHREEQDA+oCUG
CisGAQQBgjcUAgOgFwwVb2ZmaWNlQGNlcnRkaWdpdGFsLnJvgRVvZmZpY2VAY2Vy
dGRpZ2l0YWwucm8wEwYDVR0lBAwwCgYIKwYBBQUHAwkwDwYJKwYBBQUHMAEFBAIF
ADAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIGwDALBgkqhkiG9w0BAQsDggEB
AGISZKF5Ml1xDAF576/efEv5FvZdDHDzJUw/bWlYMzhAwmTl7KDH8fJj82hMJxX1
Sjqq90pg6I1uZc839im1Ldgfc9CmKW8sAX0qX+ib62cipslnBl7gWPPS5FY6Tr7w
8nxdo8Q5Y9LYMTP7IknFKLVShkeLLMEv0TdlsQuCGb7utE51BJY9zhPFDAJxiFBu
lzm2/YPTGBgHcNVgYbiklDpsv1ROsNJK8IYXwUAlLZQCTyXTp06OBuN6Nst//LwY
WtMVvkUEMfjfJl3Vj2xHudqZZRE0qFopXAvrysgEzztpQ8nQMbCAoaHzrlhtCC1G
XPKVItoiHkqP9zckhd6b4ho=
-----END CERTIFICATE-----';

        $x509 = X509::load($cert)->toArray();

        $this->assertIsArray($x509);
    }

    public function testLooseDNComparison(): void
    {
        X509::looseDNComparison();
        X509::ignoreKeyUsage();
        X509::ignoreBasicConstraints();
        $x509 = new X509();
        $x509->addDNProp('O', 'phpseclib test');
        // by default DN's are added as UTF8Strings, if the type is not explicitly specified
        $this->assertInstanceOf(UTF8String::class, $x509->getSubjectDNProps('O')[0]);
        $this->assertInstanceOf(UTF8String::class, $x509->getIssuerDNProps('O')[0]);
        $this->assertTrue($x509->isIssuerOf($x509));
        $x509->removeSubjectDNProps('O');
        $this->assertFalse($x509->isIssuerOf($x509));
        $x509->addSubjectDNProp('O', new PrintableString('phpseclib test'));
        $this->assertInstanceOf(PrintableString::class, $x509->getSubjectDNProps('O')[0]);
        $this->assertInstanceOf(UTF8String::class, $x509->getIssuerDNProps('O')[0]);
        $this->assertTrue($x509->isIssuerOf($x509));
        X509::strictDNComparison();
        $this->assertFalse($x509->isIssuerOf($x509));
        // restore orig validation behavior
        X509::checkKeyUsage();
        X509::checkBasicConstraints();
    }

    public function testSetPostalAddress(): void
    {
        $x509 = new X509();
        $address = [
            'John Doe',
            '111 Anywhere St',
            'New York, NY 10001',
        ];
        $x509->addDNProp('id-at-postalAddress', $address);
        X509::load("$x509");
        $result = $x509->getDNProps('id-at-postalAddress')[0];
        foreach ($address as $i=>$expected) {
            $this->assertSame($expected, (string) $result[$i]);
        }
    }

    public function testExtensionManagement(): void
    {
        $cert = '-----BEGIN CERTIFICATE-----
MIIDtTCCAp2gAwIBAgICECEwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMx
ITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28g
RGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNjAyMDcx
NzI0MDBaFw0yNDAxMDYwNjQ0NThaMHkxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJD
QTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEUMBIGA1UEChMLR29vZ2xlIEluYy4x
GDAWBgNVBAsTD0dvb2dsZSBSZXNlYXJjaDEVMBMGA1UEAxQMKi5nb29nbGUuY29t
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAxUWTaM/RKjoA8urhPYXr
Nh2Oz9HA88XkFIxhD3pm80wBlTTTnymSJJVWKpEJO7OyengVFRIv7U19VAFd8VCh
TCiFl7a4hsiWWQi3zh/NYgj0BnweNriblknBKTze6te1DP8otZ22qBUmhCR27aER
MWE9urWLwMIuJN/hxK234MljS9lBB3fv52RrZzSftga/P5zK34ZOlbnGcLbtoKR3
p0uWakBZM8u/665hQ4u4+YkA2kJy5YSF6wXpYKl29/mj1w9ODJTUFj3KmliiGXeo
2IhYLu4Pq52D7OKjDvKZRKK6tOM8Pii1c310ljlCewCuF/Oy/ygbNmaJG7J8/jTA
pwIBA6NfMF0wDAYDVR0TAQH/BAIwADANBgNVHREEBjAEggJhKzAdBgNVHQ4EFgQU
Zd/yRfldVXIxnAKzGaO6vZrb2XswHwYDVR0jBBgwFoAU4J1tAjJyIZ/+BvOatp4W
N1Fo5MMwDQYJKoZIhvcNAQELBQADggEBAAcwSIxKQegRqCs7adDb3VbqP1Ld0dA6
FydwendbN1P4NaqqdM89NhpOVZ5g60eM4sc08m5oZIMWqjwp3Gyf2pqM2FMQ02zi
1lMRb+t9rtjtZXCdcTjuwySYXw7M7NM0Lxhv7yN9+Vben1RTBWFghk8y4t6sai5L
68hFu+fkQzKIpHE/9cdBS+rtqyCrNit3kvqVhVpGECTS2flTBHnCe7mINojSTOsB
JYhGgW6KsKViE0hzQB8dSAcNcfwQPSKzOd02crXdJ7uYvZZK9prN83Oe1iDaizeA
1ntA2AzsC0OGg/ekAnAlxia3mzcJv0PgxRpSG7xjWSL+FVFTTs2I/wk=
-----END CERTIFICATE-----';
        $x509 = X509::load($cert);
        $this->assertSame(4, count($x509->listExtensions()));
        $ext = $x509->getExtension('id-ce-subjectAltName');
        $this->assertEquals($ext['extnValue'],$x509['tbsCertificate']['extensions'][1]['extnValue']);
        $this->assertNotEquals($ext['extnValue'],$x509['tbsCertificate']['extensions'][2]['extnValue']);
    }
}
