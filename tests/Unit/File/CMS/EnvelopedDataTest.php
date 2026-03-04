<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\File\CMS;

use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\Random;
use phpseclib4\Crypt\RSA;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\File\CMS;
use phpseclib4\File\X509;
use phpseclib4\Tests\PhpseclibTestCase;

class EnvelopedDataTest extends PhpseclibTestCase
{
    public function testPasswordDecrypt(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIHYBgkqhkiG9w0BBwOggcowgccCAQMxgYOjgYACAQCgGwYJKoZIhvcNAQUMMA4E
CBuhs+/xdgLeAgIIADAsBgsqhkiG9w0BCRADCTAdBglghkgBZQMEASoEEAYanfX/
7EvrAQFFnc0+EEgEMEeg4tDzHVLPTXAUjcSGYqLei/zHji3tvJ+hdZew3/K2XTS0
fE8HfBc01uw9GxuidTA8BgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBD3cN7fUkmZ
iq8UL3JxiWPigBC7AYnIQlC/X7rq8bcaeP9y
-----END
 CMS-----');
        // https://xkcd.com/936/
        $decrypted = $cms->getRecipients()[0]->withPassword('correct horse battery staple')->decrypt();
        $this->assertEquals("hello, world!\n", $decrypted);
    }

    public function testKeyDecrypt(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIGYBgkqhkiG9w0BBwOggYowgYcCAQIxRKJCAgEEMAYEBN6tvu8wCwYJYIZIAWUD
BAEFBCjqhj9+hBlqboSO9UybVUyjmeQ4eX8y/0x/s9JsdsWxTrrx1zNiFNzaMDwG
CSqGSIb3DQEHATAdBglghkgBZQMEASoEEA2rq3jrXhfcwE8Doq+lErqAEFqBE6fW
17lonTkG3xsJwzY=
-----END CMS-----');
        $decrypted = $cms->getRecipients()[0]->withKey(hex2bin('00112233445566778899AABBCCDDEEFF'))->decrypt();
        $this->assertEquals("hello, world!\n", $decrypted);
    }

    public function testNewPassword(): void
    {
        $plaintext = 'zzz';
        $password = 'password';
        $cms = new CMS\EncryptedData($plaintext);
        //CMS\EncryptedData::setPRF('id-hmacWithSHA1');
        $recipient = $cms->createNewRecipientFromPassword($password);
        $decrypted = $recipient->withPassword($password)->decrypt();
        $this->assertEquals($plaintext, $decrypted);
        $cms = CMS::load("$cms");
        $decrypted = $cms->getRecipients()[0]->withPassword($password)->decrypt();
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testNewKey(): void
    {
        $plaintext = 'zzz';
        $key = str_repeat('z', 16);
        $identifier = 'zzz';
        $cms = new CMS\EncryptedData('zzz');
        $recipient = $cms->createNewRecipientFromKeyWithIdentifier($key, $identifier);
        $decrypted = $recipient->withKey($key)->decrypt();
        $this->assertEquals($plaintext, $decrypted);
        $cms = CMS::load("$cms");
        $decrypted = $cms->getRecipients()[0]->withKey($key)->decrypt();
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testOAEPNonDefaultDecrypt(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIIB5QYJKoZIhvcNAQcDoIIB1jCCAdICAQAxggGNMIIBiQIBADAxMBkxFzAVBgNV
BAoMDnBocHNlY2xpYiBkZW1vAhQUmW9WEnSW1a7eA4g8v5VmosxSWjBNBgkqhkiG
9w0BAQcwQKANMAsGCWCGSAFlAwQCAaEaMBgGCSqGSIb3DQEBCDALBglghkgBZQME
AgGiEzARBgkqhkiG9w0BAQkEBN6tvu8EggEAsghgvuVW4O2ydVFNTiHSU1yvmy3N
kwVsm7ky+h8cAP3wdhj5/ma8zZGW7smQiZqB+shbRJxGoMdTYC4suoQtLw5zDYrh
vgyjzlTeuO83luhPajrxD3zJtsVfTDCXMBrHcrA4Qp3T4iw+6yTpO5aGURx5GOaJ
JVwT1UtE9zkckcqpdEZ5dE5n2IqaEpNb+vBSUtp3mywpSxbYUwUcu7GdZuNRak7U
d593XmMUapEDb22xPCAP0y4ascbTCI7ypnRVMCAeBwq1ooyUVpcKmPtumMwW8Dns
BFFqLF/dLsX5qL/L3yeHHe3uyc3V5MErsIx01yL4fitg00fpJbSprUyGijA8Bgkq
hkiG9w0BBwEwHQYJYIZIAWUDBAEqBBD7Rx2WY+sd2rOghpJ8JjgkgBB9XGoGYzbk
HZ5LFXx7/Cul
-----END CMS-----');
        $private = '-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDNuYD130WlsYxC
OekHh70j9TML61KIlV+sEunB573QkRkJwuZW36qRXF2Gm/PYU1n1vMXJxL3DxJc+
i0vMmp3/CYVhQ36WTAHN0otL2KZ8Ppcul2Icjzee0/ulc0+f8G8twbe7HIyAHcrH
V4af1yV4r4P07GMMiFLFcC3KRysfD+bukSw/AkViomLodeWNpxe1ipk6uyowv3zL
VWK31NZeYD099yACq2v2l6fbX/+TCnz1gPiNyFb27wx7HeLzwa27G8MMkwgCXUf4
oUmaq6qSc8tmF2jBx+i/n7rxJwfqVZjsZQ/CsABr7obn8eXJ0pRSwReAu6NsaQXZ
ntTqKCwZAgMBAAECggEAD2uMggwmm/aEoouABGN6nDu12XqIaNp2yF7GjL/tF2QO
MhAc1H2BZdHm5L8YdlTmalKoVKkIPFNRBDbMC126OAf4/8MKYFj5eE8EHT7zrl5s
AJRc80e84zfVJfVQY5b8Y7v1z0hNiRDdRoyF98HYT4UrE+xgDuwXoDBPY65qn1z0
ODRLGhixNjxMeYuMJ0c4iwRHzNuf0rgsxVqMF4YKCmX52ivnabcamK5I3uVRJ012
V0WuprDu5PK8DwZ4kAEFkZrAp5j0+2pamRTGAONNrCyJ08QyMr/4QesyrQh4o5oU
JbSarHkGUc7bdNBIfO7sa6HpUkZcmd3oXpJMac6nfQKBgQD8ZObTQdgXzFlVg8r4
/8LWrYgMGhacHrwSBYD396oZxhXKQc5DoDFYVaKr4azNLEPHlwg+D6f2p7XC5y0K
+luJYb5+87JYreQyxeqQxKf8LkL2YYysT2JohOzDMZy467gEr+pQ4wngsJ8xUSQT
wMz2HzGD8Wa5nneU/Z1I4eQWXwKBgQDQqeoZ+wELVbCZmsuZAfbQ2lC/sB/fZuge
YZk1v08VKljseMa3t2mlBRdMaYa5U4yEGcRiXcSklaqHujMMsEU2BIqKEVL1G7Qg
gGDryT92EPi0nzJnuumkv9xVG0mZtFnPPX/9RGITAdzYFOXmDZGy2B5jRocoS1ZE
w3pQCzughwKBgFOjxHKBwXCxgXE7SYoWh6TIwOrxwkheTwjR1hlWc4IzCImMISR7
855IUq4PDUq4voVn4Y1fdtPgY/WA0oZuzOLMB2req12D0rmYqNDsupZxZjNrxEhd
zkjAtA1DZaJKSyMSgN3pPx68qSSYtRHutH1jfO8ykk4023/+Q58hbIqVAoGAO4HZ
k2Mz3wmm/YdZvN8EhndcQ+50iH+OfuuSh/NxGDYlefrPoSEbbcZP6KjHlR6wmhPH
H85iABX2thJx8JJsioUtBUb/g4tNCV/TRCr2gDNC2i/0bgSuER/uNA8+JCl8209M
quvPlGAZnT4Iel0wSfK8Z897SBCEH8Qno6Awdw0CgYADee+vbUaR6RdTLYmsBPQ/
RXpiuPiHQ39YHiujaDk3BGw9igX1G3lHR0gQIG1sbsudt8FXFfdlWfT4MUVWGlBm
FndAlFnyh782RoE6ORRHxKgaO1qomK0ewReUTrO6mEt1SdbQDAHJX8XU2ro43Xl9
9zr18xnnbU90RsMHUYLBWg==
-----END PRIVATE KEY-----';
        $private = PublicKeyLoader::load($private);
        $decrypted = $cms->getRecipients()[0]->withKey($private)->decrypt();
        $this->assertEquals("hello, world!\n", $decrypted);
    }

    public function testOAEPDefaultDecrypt(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIIBpQYJKoZIhvcNAQcDoIIBljCCAZICAQAxggFNMIIBSQIBADAxMBkxFzAVBgNV
BAoMDnBocHNlY2xpYiBkZW1vAhQUmW9WEnSW1a7eA4g8v5VmosxSWjANBgkqhkiG
9w0BAQcwAASCAQBTV83CKlkadLT0VWW6R1zOmE3F0Ktt7jnpmElMSJqLwBrdK3ek
KJi8O0ZL1aEcgXjpXL/OwDzXL75ul6G7czJzhb8rSlQzAOEwRTmr4mcDbK18DAbi
pGIyO9GUZALW1PprAUnMr84YFcLMHHZz2AIUF//hkHF0DTMIKMLxXFPFJgqMs1p+
dmctufj2xnjf4xoMymZOjBeNjPS9wKwVE4i+eQM9ypvb/snNkQjChP2vkV3XnQYs
IVp6xHhboPdJUYCfl6N9TNBiOfe8plIzF9RHaK6nkpvQTo65sHkONmPlVgVRR2Y+
FVP+fgAkronEDy0Fvsf+SZowzDmkePUpOLm0MDwGCSqGSIb3DQEHATAdBglghkgB
ZQMEASoEENT+JKlPzTt9W5WAA3IfobuAEHMqwb2kybltmkkaG2LJi9c=
-----END CMS-----');
        $private = '-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDNuYD130WlsYxC
OekHh70j9TML61KIlV+sEunB573QkRkJwuZW36qRXF2Gm/PYU1n1vMXJxL3DxJc+
i0vMmp3/CYVhQ36WTAHN0otL2KZ8Ppcul2Icjzee0/ulc0+f8G8twbe7HIyAHcrH
V4af1yV4r4P07GMMiFLFcC3KRysfD+bukSw/AkViomLodeWNpxe1ipk6uyowv3zL
VWK31NZeYD099yACq2v2l6fbX/+TCnz1gPiNyFb27wx7HeLzwa27G8MMkwgCXUf4
oUmaq6qSc8tmF2jBx+i/n7rxJwfqVZjsZQ/CsABr7obn8eXJ0pRSwReAu6NsaQXZ
ntTqKCwZAgMBAAECggEAD2uMggwmm/aEoouABGN6nDu12XqIaNp2yF7GjL/tF2QO
MhAc1H2BZdHm5L8YdlTmalKoVKkIPFNRBDbMC126OAf4/8MKYFj5eE8EHT7zrl5s
AJRc80e84zfVJfVQY5b8Y7v1z0hNiRDdRoyF98HYT4UrE+xgDuwXoDBPY65qn1z0
ODRLGhixNjxMeYuMJ0c4iwRHzNuf0rgsxVqMF4YKCmX52ivnabcamK5I3uVRJ012
V0WuprDu5PK8DwZ4kAEFkZrAp5j0+2pamRTGAONNrCyJ08QyMr/4QesyrQh4o5oU
JbSarHkGUc7bdNBIfO7sa6HpUkZcmd3oXpJMac6nfQKBgQD8ZObTQdgXzFlVg8r4
/8LWrYgMGhacHrwSBYD396oZxhXKQc5DoDFYVaKr4azNLEPHlwg+D6f2p7XC5y0K
+luJYb5+87JYreQyxeqQxKf8LkL2YYysT2JohOzDMZy467gEr+pQ4wngsJ8xUSQT
wMz2HzGD8Wa5nneU/Z1I4eQWXwKBgQDQqeoZ+wELVbCZmsuZAfbQ2lC/sB/fZuge
YZk1v08VKljseMa3t2mlBRdMaYa5U4yEGcRiXcSklaqHujMMsEU2BIqKEVL1G7Qg
gGDryT92EPi0nzJnuumkv9xVG0mZtFnPPX/9RGITAdzYFOXmDZGy2B5jRocoS1ZE
w3pQCzughwKBgFOjxHKBwXCxgXE7SYoWh6TIwOrxwkheTwjR1hlWc4IzCImMISR7
855IUq4PDUq4voVn4Y1fdtPgY/WA0oZuzOLMB2req12D0rmYqNDsupZxZjNrxEhd
zkjAtA1DZaJKSyMSgN3pPx68qSSYtRHutH1jfO8ykk4023/+Q58hbIqVAoGAO4HZ
k2Mz3wmm/YdZvN8EhndcQ+50iH+OfuuSh/NxGDYlefrPoSEbbcZP6KjHlR6wmhPH
H85iABX2thJx8JJsioUtBUb/g4tNCV/TRCr2gDNC2i/0bgSuER/uNA8+JCl8209M
quvPlGAZnT4Iel0wSfK8Z897SBCEH8Qno6Awdw0CgYADee+vbUaR6RdTLYmsBPQ/
RXpiuPiHQ39YHiujaDk3BGw9igX1G3lHR0gQIG1sbsudt8FXFfdlWfT4MUVWGlBm
FndAlFnyh782RoE6ORRHxKgaO1qomK0ewReUTrO6mEt1SdbQDAHJX8XU2ro43Xl9
9zr18xnnbU90RsMHUYLBWg==
-----END PRIVATE KEY-----';
        $private = PublicKeyLoader::load($private);
        $decrypted = $cms->getRecipients()[0]->withKey($private)->decrypt();
        $this->assertEquals("hello, world!\n", $decrypted);
    }

    public function testECEncrypt(): void
    {
        $plaintext = 'hello, world!';

        $private = EC::createKey('nistp256');
        $x509 = new X509($private->getPublicKey());
        $x509->setDN('O=phpseclib demo');
        $x509->makeCA();
        $private->sign($x509);

        $cms = new CMS\EncryptedData($plaintext);
        $cms->createNewRecipientFromX509($x509);

        $cms = CMS::load("$cms");
        $decrypted = $cms->getRecipients()[0]->withKey($private)->decrypt();
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testDecryptWithKeyID(): void
    {
        // decrypting a KeyAgreeRecipient EnvelopedData CMS that's using a key (as opposed to an X509 cert) as the OriginatorIdentifierOrKey
        $cms = CMS::load('-----BEGIN CMS-----
MIIBIwYJKoZIhvcNAQcDoIIBFDCCARACAQIxgcyhgckCAQOgUaFPMAkGByqGSM49
AgEDQgAE6NVhbds7w/2AG2xjrlVZ76NRK8yiwY2Us2u9K+JZyDqtnbTwD6cf1LiY
okjk6QSx2sDAvHMoxUNFrdXvjdsmQTAVBgYrgQQBDgEwCwYJYIZIAWUDBAEtMFow
WDAsMBQxEjAQBgNVBAoMCXBocHNlY2xpYgIUKRLDuszEs/BlBV+266/L36A+shAE
KPzUsswLatZSRaJzWLpp2jMcONZTtC3ErFhzjc8dH6J0iQxj+2fZq/8wPAYJKoZI
hvcNAQcBMB0GCWCGSAFlAwQBKgQQMzaRYqBVSsbhxPO4e4Y/foAQyXO01TcfsFc0
WgcC4jswvQ==
-----END CMS-----');
        $private = '-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKOdaai0zSMiTJr84
U7KyohVWB9EQknra0yo+2iSy/DWhRANCAAQ27Fn4fgxObbYz4NvIL46U62R8/yre
JXhYfxbdvEUY6P4PO+Y9EqdrGwb8gsZTWDF5Hldhcu1VO5ECp4WkLPN2
-----END PRIVATE KEY-----';

        $private = PublicKeyLoader::load($private);

        $decrypted = $cms->getRecipients()[0]->withKey($private)->decrypt();
        $this->assertEquals("hello, world!\n", $decrypted);
    }

    public function testFindRecipientsByID(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIGYBgkqhkiG9w0BBwOggYowgYcCAQIxRKJCAgEEMAYEBN6tvu8wCwYJYIZIAWUD
BAEFBCjqhj9+hBlqboSO9UybVUyjmeQ4eX8y/0x/s9JsdsWxTrrx1zNiFNzaMDwG
CSqGSIb3DQEHATAdBglghkgBZQMEASoEEA2rq3jrXhfcwE8Doq+lErqAEFqBE6fW
17lonTkG3xsJwzY=
-----END CMS-----');
        $decrypted = $cms->findRecipients("\xde\xad\xbe\xef")[0]->withKey(hex2bin('00112233445566778899AABBCCDDEEFF'))->decrypt();
        $this->assertEquals("hello, world!\n", $decrypted);
    }

    public function testFindKeyTransWithX509(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIIB5QYJKoZIhvcNAQcDoIIB1jCCAdICAQAxggGNMIIBiQIBADAxMBkxFzAVBgNV
BAoMDnBocHNlY2xpYiBkZW1vAhQUmW9WEnSW1a7eA4g8v5VmosxSWjBNBgkqhkiG
9w0BAQcwQKANMAsGCWCGSAFlAwQCAaEaMBgGCSqGSIb3DQEBCDALBglghkgBZQME
AgGiEzARBgkqhkiG9w0BAQkEBN6tvu8EggEAsghgvuVW4O2ydVFNTiHSU1yvmy3N
kwVsm7ky+h8cAP3wdhj5/ma8zZGW7smQiZqB+shbRJxGoMdTYC4suoQtLw5zDYrh
vgyjzlTeuO83luhPajrxD3zJtsVfTDCXMBrHcrA4Qp3T4iw+6yTpO5aGURx5GOaJ
JVwT1UtE9zkckcqpdEZ5dE5n2IqaEpNb+vBSUtp3mywpSxbYUwUcu7GdZuNRak7U
d593XmMUapEDb22xPCAP0y4ascbTCI7ypnRVMCAeBwq1ooyUVpcKmPtumMwW8Dns
BFFqLF/dLsX5qL/L3yeHHe3uyc3V5MErsIx01yL4fitg00fpJbSprUyGijA8Bgkq
hkiG9w0BBwEwHQYJYIZIAWUDBAEqBBD7Rx2WY+sd2rOghpJ8JjgkgBB9XGoGYzbk
HZ5LFXx7/Cul
-----END CMS-----');
        $private = '-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDNuYD130WlsYxC
OekHh70j9TML61KIlV+sEunB573QkRkJwuZW36qRXF2Gm/PYU1n1vMXJxL3DxJc+
i0vMmp3/CYVhQ36WTAHN0otL2KZ8Ppcul2Icjzee0/ulc0+f8G8twbe7HIyAHcrH
V4af1yV4r4P07GMMiFLFcC3KRysfD+bukSw/AkViomLodeWNpxe1ipk6uyowv3zL
VWK31NZeYD099yACq2v2l6fbX/+TCnz1gPiNyFb27wx7HeLzwa27G8MMkwgCXUf4
oUmaq6qSc8tmF2jBx+i/n7rxJwfqVZjsZQ/CsABr7obn8eXJ0pRSwReAu6NsaQXZ
ntTqKCwZAgMBAAECggEAD2uMggwmm/aEoouABGN6nDu12XqIaNp2yF7GjL/tF2QO
MhAc1H2BZdHm5L8YdlTmalKoVKkIPFNRBDbMC126OAf4/8MKYFj5eE8EHT7zrl5s
AJRc80e84zfVJfVQY5b8Y7v1z0hNiRDdRoyF98HYT4UrE+xgDuwXoDBPY65qn1z0
ODRLGhixNjxMeYuMJ0c4iwRHzNuf0rgsxVqMF4YKCmX52ivnabcamK5I3uVRJ012
V0WuprDu5PK8DwZ4kAEFkZrAp5j0+2pamRTGAONNrCyJ08QyMr/4QesyrQh4o5oU
JbSarHkGUc7bdNBIfO7sa6HpUkZcmd3oXpJMac6nfQKBgQD8ZObTQdgXzFlVg8r4
/8LWrYgMGhacHrwSBYD396oZxhXKQc5DoDFYVaKr4azNLEPHlwg+D6f2p7XC5y0K
+luJYb5+87JYreQyxeqQxKf8LkL2YYysT2JohOzDMZy467gEr+pQ4wngsJ8xUSQT
wMz2HzGD8Wa5nneU/Z1I4eQWXwKBgQDQqeoZ+wELVbCZmsuZAfbQ2lC/sB/fZuge
YZk1v08VKljseMa3t2mlBRdMaYa5U4yEGcRiXcSklaqHujMMsEU2BIqKEVL1G7Qg
gGDryT92EPi0nzJnuumkv9xVG0mZtFnPPX/9RGITAdzYFOXmDZGy2B5jRocoS1ZE
w3pQCzughwKBgFOjxHKBwXCxgXE7SYoWh6TIwOrxwkheTwjR1hlWc4IzCImMISR7
855IUq4PDUq4voVn4Y1fdtPgY/WA0oZuzOLMB2req12D0rmYqNDsupZxZjNrxEhd
zkjAtA1DZaJKSyMSgN3pPx68qSSYtRHutH1jfO8ykk4023/+Q58hbIqVAoGAO4HZ
k2Mz3wmm/YdZvN8EhndcQ+50iH+OfuuSh/NxGDYlefrPoSEbbcZP6KjHlR6wmhPH
H85iABX2thJx8JJsioUtBUb/g4tNCV/TRCr2gDNC2i/0bgSuER/uNA8+JCl8209M
quvPlGAZnT4Iel0wSfK8Z897SBCEH8Qno6Awdw0CgYADee+vbUaR6RdTLYmsBPQ/
RXpiuPiHQ39YHiujaDk3BGw9igX1G3lHR0gQIG1sbsudt8FXFfdlWfT4MUVWGlBm
FndAlFnyh782RoE6ORRHxKgaO1qomK0ewReUTrO6mEt1SdbQDAHJX8XU2ro43Xl9
9zr18xnnbU90RsMHUYLBWg==
-----END PRIVATE KEY-----';

        $x509 = new X509();
        $x509->setDN($cms->getRecipients()[0]['rid']['issuerAndSerialNumber']['issuer']->toArray());
        $x509->setSerialNumber($cms->getRecipients()[0]['rid']['issuerAndSerialNumber']['serialNumber']);
        $x509->setExtension('id-ce-keyUsage', ['keyEncipherment']);

        $private = PublicKeyLoader::load($private);
        $decrypted = $cms->findRecipients($x509)[0]->withKey($private)->decrypt();
        $this->assertEquals("hello, world!\n", $decrypted);
    }

    public function testFindKeyAgreementWithX509(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIIBIwYJKoZIhvcNAQcDoIIBFDCCARACAQIxgcyhgckCAQOgUaFPMAkGByqGSM49
AgEDQgAE6NVhbds7w/2AG2xjrlVZ76NRK8yiwY2Us2u9K+JZyDqtnbTwD6cf1LiY
okjk6QSx2sDAvHMoxUNFrdXvjdsmQTAVBgYrgQQBDgEwCwYJYIZIAWUDBAEtMFow
WDAsMBQxEjAQBgNVBAoMCXBocHNlY2xpYgIUKRLDuszEs/BlBV+266/L36A+shAE
KPzUsswLatZSRaJzWLpp2jMcONZTtC3ErFhzjc8dH6J0iQxj+2fZq/8wPAYJKoZI
hvcNAQcBMB0GCWCGSAFlAwQBKgQQMzaRYqBVSsbhxPO4e4Y/foAQyXO01TcfsFc0
WgcC4jswvQ==
-----END CMS-----');
        $private = '-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKOdaai0zSMiTJr84
U7KyohVWB9EQknra0yo+2iSy/DWhRANCAAQ27Fn4fgxObbYz4NvIL46U62R8/yre
JXhYfxbdvEUY6P4PO+Y9EqdrGwb8gsZTWDF5Hldhcu1VO5ECp4WkLPN2
-----END PRIVATE KEY-----';

        $private = PublicKeyLoader::load($private);

        $x509 = new X509();
        $x509->setDN($cms->getRecipients()[0]['rid']['issuerAndSerialNumber']['issuer']->toArray());
        $x509->setSerialNumber($cms->getRecipients()[0]['rid']['issuerAndSerialNumber']['serialNumber']);
        $x509->setExtension('id-ce-keyUsage', ['keyAgreement']);

        $decrypted = $cms->findRecipients($x509)[0]->withKey($private)->decrypt();
        $this->assertEquals("hello, world!\n", $decrypted);
    }

    public function testDecryptWithKey(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIGYBgkqhkiG9w0BBwOggYowgYcCAQIxRKJCAgEEMAYEBN6tvu8wCwYJYIZIAWUD
BAEFBCjqhj9+hBlqboSO9UybVUyjmeQ4eX8y/0x/s9JsdsWxTrrx1zNiFNzaMDwG
CSqGSIb3DQEHATAdBglghkgBZQMEASoEEA2rq3jrXhfcwE8Doq+lErqAEFqBE6fW
17lonTkG3xsJwzY=
-----END CMS-----');
        $decrypted = $cms->deriveFromKey(hex2bin('00112233445566778899AABBCCDDEEFF'))->decrypt();
        $this->assertEquals("hello, world!\n", $decrypted);
    }

    public function testCertAddition(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MIIB5QYJKoZIhvcNAQcDoIIB1jCCAdICAQAxggGNMIIBiQIBADAxMBkxFzAVBgNV
BAoMDnBocHNlY2xpYiBkZW1vAhQUmW9WEnSW1a7eA4g8v5VmosxSWjBNBgkqhkiG
9w0BAQcwQKANMAsGCWCGSAFlAwQCAaEaMBgGCSqGSIb3DQEBCDALBglghkgBZQME
AgGiEzARBgkqhkiG9w0BAQkEBN6tvu8EggEAsghgvuVW4O2ydVFNTiHSU1yvmy3N
kwVsm7ky+h8cAP3wdhj5/ma8zZGW7smQiZqB+shbRJxGoMdTYC4suoQtLw5zDYrh
vgyjzlTeuO83luhPajrxD3zJtsVfTDCXMBrHcrA4Qp3T4iw+6yTpO5aGURx5GOaJ
JVwT1UtE9zkckcqpdEZ5dE5n2IqaEpNb+vBSUtp3mywpSxbYUwUcu7GdZuNRak7U
d593XmMUapEDb22xPCAP0y4ascbTCI7ypnRVMCAeBwq1ooyUVpcKmPtumMwW8Dns
BFFqLF/dLsX5qL/L3yeHHe3uyc3V5MErsIx01yL4fitg00fpJbSprUyGijA8Bgkq
hkiG9w0BBwEwHQYJYIZIAWUDBAEqBBD7Rx2WY+sd2rOghpJ8JjgkgBB9XGoGYzbk
HZ5LFXx7/Cul
-----END CMS-----');

        $x509 = new X509();
        $x509->setDN($cms->getRecipients()[0]['rid']['issuerAndSerialNumber']['issuer']->toArray());
        $x509->setSerialNumber($cms->getRecipients()[0]['rid']['issuerAndSerialNumber']['serialNumber']);
        $x509->setExtension('id-ce-keyUsage', ['keyEncipherment']);

        $cms->addCertificate($x509);

        $cms = CMS::load("$cms");
        $this->assertEquals("$x509", (string) $cms->getCertificates()[0]);
    }

    public function testMultiRecipients(): void
    {
        $plaintext = 'hello, world!';

        $ec = EC::createKey('nistp256');
        $x509 = new X509($ec->getPublicKey());
        $ec->sign($x509);

        $rsa = RSA::createKey(2048);
        $x509a = new X509($rsa->getPublicKey());
        $rsa->sign($x509a);

        $key = Random::string(16);
        $cms = new CMS\EncryptedData($plaintext, key: $key);
        $cms->createNewRecipientFromPassword('password');
        $cms->createNewRecipientFromKeyWithIdentifier(str_repeat('x', 16), 'zzz');
        $cms->createNewRecipientFromX509($x509a);
        $cms->createNewRecipientFromX509($x509);
        $cms = CMS::load("$cms");
        $this->assertEquals($plaintext, $cms->deriveFromKey($ec)->decrypt());
        $this->assertEquals($plaintext, $cms->deriveFromKey(str_repeat('x', 16))->decrypt());
        $this->assertEquals($plaintext, $cms->deriveFromKey($rsa)->decrypt());
        $this->assertEquals($plaintext, $cms->deriveFromPassword('password')->decrypt());
        $this->assertEquals($plaintext, $cms->withKey($key)->decrypt());
    }
}
