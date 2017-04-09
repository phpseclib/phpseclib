<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\File\ASN1;
use phpseclib\File\ASN1\Element;
use phpseclib\File\X509;
use phpseclib\Crypt\RSA;

class Unit_File_X509_X509Test extends PhpseclibTestCase
{
    public function testExtensionMapping()
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

        $x509 = new X509();

        $cert = $x509->loadX509($test);

        $this->assertInternalType('array', $cert['tbsCertificate']['extensions'][3]['extnValue']);
    }

    public function testLoadUnsupportedExtension()
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

        $x509 = new X509();

        $cert = $x509->loadX509($test);

        $this->assertEquals('MDUwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAHBgUrDgMCBzAKBggqhkiG9w0DBw==', $cert['tbsCertificate']['extensions'][8]['extnValue']);
    }

    public function testSaveUnsupportedExtension()
    {
        $x509 = new X509();
        $cert = $x509->loadX509('-----BEGIN CERTIFICATE-----
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

        $asn1 = new ASN1();

        $value = $this->_encodeOID('1.2.3.4');
        $ext = chr(ASN1::TYPE_OBJECT_IDENTIFIER) . $asn1->_encodeLength(strlen($value)) . $value;
        $value = 'zzzzzzzzz';
        $ext.= chr(ASN1::TYPE_OCTET_STRING) . $asn1->_encodeLength(strlen($value)) . $value;
        $ext = chr(ASN1::TYPE_SEQUENCE | 0x20) . $asn1->_encodeLength(strlen($ext)) . $ext;

        $cert['tbsCertificate']['extensions'][4] = new Element($ext);

        $result = $x509->loadX509($x509->saveX509($cert));

        $this->assertCount(5, $result['tbsCertificate']['extensions']);
    }

    /**
     * @group github705
     */
    public function testSaveNullRSAParam()
    {
        $privKey = new RSA();
        $privKey->loadKey('-----BEGIN RSA PRIVATE KEY-----
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

        $pubKey = new RSA();
        $pubKey->loadKey($privKey->getPublicKey());
        $pubKey->setPublicKey();

        $subject = new X509();
        $subject->setDNProp('id-at-organizationName', 'phpseclib demo cert');
        $subject->setPublicKey($pubKey);

        $issuer = new X509();
        $issuer->setPrivateKey($privKey);
        $issuer->setDN($subject->getDN());

        $x509 = new X509();

        $result = $x509->sign($issuer, $subject);
        $cert = $x509->saveX509($result);
        $cert = $x509->loadX509($cert);

        $this->assertArrayHasKey('parameters', $cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']);
        $this->assertArrayHasKey('parameters', $cert['signatureAlgorithm']);
        $this->assertArrayHasKey('parameters', $cert['tbsCertificate']['signature']);
    }

    private function _encodeOID($oid)
    {
        if ($oid === false) {
            user_error('Invalid OID');
            return false;
        }
        $value = '';
        $parts = explode('.', $oid);
        $value = chr(40 * $parts[0] + $parts[1]);
        for ($i = 2; $i < count($parts); $i++) {
            $temp = '';
            if (!$parts[$i]) {
                $temp = "\0";
            } else {
                while ($parts[$i]) {
                    $temp = chr(0x80 | ($parts[$i] & 0x7F)) . $temp;
                    $parts[$i] >>= 7;
                }
                $temp[strlen($temp) - 1] = $temp[strlen($temp) - 1] & chr(0x7F);
            }
            $value.= $temp;
        }
        return $value;
    }

    public function testGetOID()
    {
        $x509 = new X509();
        $this->assertEquals($x509->getOID('2.16.840.1.101.3.4.2.1'), '2.16.840.1.101.3.4.2.1');
        $this->assertEquals($x509->getOID('id-sha256'), '2.16.840.1.101.3.4.2.1');
        $this->assertEquals($x509->getOID('zzz'), 'zzz');
    }

    public function testIPAddressSubjectAltNamesDecoding()
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

        $x509 = new X509();
        $cert = $x509->loadX509($test);
        $this->assertEquals($cert['tbsCertificate']['extensions'][3]['extnValue'][0]['iPAddress'], '204.152.200.250');
        $this->assertEquals($cert['tbsCertificate']['extensions'][3]['extnValue'][1]['iPAddress'], '2001:470:f309:9::3');
    }

    public function testPostalAddress()
    {
        $x509 = new X509();
        $decoded = $x509->loadX509('-----BEGIN CERTIFICATE-----
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
Mj93S
-----END CERTIFICATE-----');
        $x509->loadX509($x509->saveX509($decoded));
        $expected = array(
            array(
                array('utf8String' => "Al. Marsza\xC5\x82ka Pi\xC5\x82sudskiego 52/54"),
                array('utf8String' => '81-382 Gdynia'),
                array('utf8String' => 'Polska'),
                array('utf8String' => 'pomorskie')
            )
        );
        $this->assertEquals($x509->getDNProp('id-at-postalAddress'), $expected);

        $expected = "C=PL, O=Urz\xC4\x85d Miasta Gdyni/serialNumber=PESEL: 61060603118, CN=Jerzy Przeworski/postalAddress=" . '0F\X0C"AL. MARSZA\XC5\X82KA PI\XC5\X82SUDSKIEGO 52/54\X0C\X0D81-382 GDYNIA\X0C\X06POLSKA\X0C\X09POMORSKIE/givenName=Jerzy, SN=Przeworski';
        $this->assertEquals($x509->getDN(X509::DN_STRING), $expected);
    }

    public function testStrictComparison()
    {
        $x509 = new X509();
        $x509->loadCA('-----BEGIN CERTIFICATE-----
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

        $x509->loadX509('-----BEGIN CERTIFICATE-----
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
Mj93S
-----END CERTIFICATE-----');
        $this->assertFalse($x509->validateSignature());
    }

    public function testLooseComparison()
    {
        if (!extension_loaded('runkit')) {
            return false;
        }

        define('FILE_X509_IGNORE_TYPE', true);

        $x509 = new X509();
        $x509->loadCA('-----BEGIN CERTIFICATE-----
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

        $x509->loadX509('-----BEGIN CERTIFICATE-----
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
Mj93S
-----END CERTIFICATE-----');
        $this->assertTrue($x509->validateSignature());

        runkit_constant_remove('FILE_X509_IGNORE_TYPE');
    }

    // fixed by #1104
    public function testMultipleDomainNames()
    {
        $keyGenerator = new RSA();
        $keys = $keyGenerator->createKey(512);

        $privateKey = new RSA();
        $privateKey->loadKey($keys['privatekey']);

        $publicKey = new RSA();
        $publicKey->loadKey($keys['publickey']);
        $publicKey->setPublicKey();

        $subject = new X509();
        $subject->setDomain('example.com', 'example.net');

        $subject->setPublicKey($publicKey);

        $issuer = new X509();
        $issuer->setPrivateKey($privateKey);
        $issuer->setDN($subject->getDN());

        $x509 = new X509();
        $x509->sign($issuer, $subject);
    }

    public function testUtcTimeWithoutSeconds()
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

        $x509 = new X509();

        $cert = $x509->loadX509($test);

        $this->assertEquals($cert['tbsCertificate']['validity']['notBefore']['utcTime'], 'Tue, 07 Jan 2014 00:00:00 +0000');
        $this->assertEquals($cert['tbsCertificate']['validity']['notAfter']['utcTime'], 'Fri, 01 Apr 2016 07:00:00 +0000');
    }
}
