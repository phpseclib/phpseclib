<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2013 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'Crypt/RSA.php';

class Unit_Crypt_RSA_LoadKeyTest extends PhpseclibTestCase
{
    public function testBadKey()
    {
        $rsa = new Crypt_RSA();

        $key = 'zzzzzzzzzzzzzz';

        $this->assertFalse($rsa->loadKey($key));
    }

    public function testPKCS1Key()
    {
        $rsa = new Crypt_RSA();

        $key = '-----BEGIN RSA PRIVATE KEY-----
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

        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPrivateKey());
    }

    public function testPKCS1SpacesKey()
    {
        $rsa = new Crypt_RSA();

        $key = '-----BEGIN RSA PRIVATE KEY-----
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
        $key = str_replace(array("\r", "\n", "\r\n"), ' ', $key);

        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPrivateKey());
    }

    public function testPKCS1NoHeaderKey()
    {
        $rsa = new Crypt_RSA();

        $key = 'MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=';

        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPrivateKey());
    }

    public function testPKCS1NoWhitespaceNoHeaderKey()
    {
        $rsa = new Crypt_RSA();

        $key = 'MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp' .
               'wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5' .
               '1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh' .
               '3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2' .
               'pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX' .
               'GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il' .
               'AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF' .
               'L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k' .
               'X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl' .
               'U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ' .
               '37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=';

        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPrivateKey());
    }

    public function testRawPKCS1Key()
    {
        $rsa = new Crypt_RSA();

        $key = 'MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp' .
               'wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5' .
               '1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh' .
               '3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2' .
               'pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX' .
               'GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il' .
               'AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF' .
               'L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k' .
               'X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl' .
               'U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ' .
               '37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=';
        $key = base64_decode($key);

        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPrivateKey());
    }

    public function testLoadPKCS8PrivateKey()
    {
        $rsa = new Crypt_RSA();
        $rsa->setPassword('password');

        $key = '-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE6TAbBgkqhkiG9w0BBQMwDgQIcWWgZeQYPTcCAggABIIEyLoa5b3ktcPmy4VB
hHkpHzVSEsKJPmQTUaQvUwIp6+hYZeuOk78EPehrYJ/QezwJRdyBoD51oOxqWCE2
fZ5Wf6Mi/9NIuPyqQccP2ouErcMAcDLaAx9C0Ot37yoG0S6hOZgaxqwnCdGYKHgS
7cYUv40kLOJmTOJlHJbatfXHocrHcHkCBJ1q8wApA1KVQIZsqmyBUBuwbrfFwpC9
d/R674XxCWJpXvU63VNZRFYUvd7YEWCrdSeleb99p0Vn1kxI5463PXurgs/7GPiO
SLSdX44DESP9l7lXenC4gbuT8P0xQRDzGrB5l9HHoV3KMXFODWTMnLcp1nuhA0OT
fPS2yzT9zJgqHiVKWgcUUJ5uDelVfnsmDhnh428p0GBFbniH07qREC9kq78UqQNI
Kybp4jQ4sPs64zdYm/VyLWtAYz8QNAKHLcnPwmTPr/XlJmox8rlQhuSQTK8E+lDr
TOKpydrijN3lF+pgyUuUj6Ha8TLMcOOwqcrpBig4SGYoB56gjAO0yTE9uCPdBakj
yxi3ksn51ErigGM2pGMNcVdwkpJ/x+DEBBO0auy3t9xqM6LK8pwNcOT1EWO+16zY
79LVSavc49t+XxMc3Xasz/G5xQgD1FBp6pEnsg5JhTTG/ih6Y/DQD8z3prjC3qKc
rpL4NA9KBI/IF1iIXlrfmN/zCKbBuEOEGqwcHBDHPySZbhL2XLSpGcK/NBl1bo1Z
G+2nUTauoC67Qb0+fnzTcvOiMNAbHMiqkirs4anHX33MKL2gR/3dp8ca9hhWWXZz
Mkk2FK9sC/ord9F6mTtvTiOSDzpiEhb94uTxXqBhIbsrGXCUUd0QQN5s2dmW2MfS
M35KeSv2rwDGzC1+Qf3MhHGIZDqoQwuZEzM5yHHafCatAbZd2sjaFWegg0r2ca7a
eZkZFj3ZuDYXJFnL82guOASh7rElWO2Ys7ncXAKnaV3WkkF+JDv/CUHr+Q/h6Ae5
qEvgubTCVSYHzRP37XJItlcdywTIcTY+t6jymmyEBJ66LmUoD47gt/vDUSbhT6Oa
GlcZ+MZGlUnPOSq4YknOgwKH8izboY4UgVCrmXvlaZYQhZemNDkVbpYVDf+s6cPf
tJwVoZf+qf2SsRTUsI10isoIzCyGw2ie8kmipdP434Z/99uVU3zxD6raNDlyp33q
FWMgpr2JU6NVAla7N51g7Jk8VjIIn7SvCYyWkmvv4kLB1UHl3NFqYb9YuIZUaDyt
j/NMcKMLLOaEorRZ2N2mDNoihMxMf8J3J9APnzUigAtaalGKNOrd2Fom5OVADePv
Tb5sg1uVQzfcpFrjIlLVh+2cekX0JM84phbMpHmm5vCjjfYvUvcMy0clCf0x3jz6
LZf5Fzc8xbZmpse5OnOrsDLCNh+SlcYOzsagSZq4TgvSeI9Tr4lv48dLJHCCcYKL
eymS9nhlCFuuHbi7zI7edcI49wKUW1Sj+kvKq3LMIEkMlgzqGKA6JqSVxHP51VH5
FqV4aKq70H6dNJ43bLVRPhtF5Bip5P7k/6KIsGTPUd54PHey+DuWRjitfheL0G2w
GF/qoZyC1mbqdtyyeWgHtVbJVUORmpbNnXOII9duEqBUNDiO9VSZNn/8h/VsYeAB
xryZaRDVmtMuf/OZBQ==
-----END ENCRYPTED PRIVATE KEY-----';

        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPrivateKey());
    }

    public function testSavePKCS8PrivateKey()
    {
        $rsa = new Crypt_RSA();

        $key = '-----BEGIN RSA PRIVATE KEY-----
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
        $rsa->setPassword('password');

        $this->assertTrue($rsa->loadKey($key));

        $key = $rsa->getPrivateKey(CRYPT_RSA_PRIVATE_FORMAT_PKCS8);
        $this->assertIsString($key);

        $this->assertTrue($rsa->loadKey($key));
    }

    public function testPubKey1()
    {
        $rsa = new Crypt_RSA();

        $key = '-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA61BjmfXGEvWmegnBGSuS+rU9soUg2FnODva32D1AqhwdziwHINFa
D1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBSEVCgJjtHAGZIm5GL/KA86KDp/CwDFMSw
luowcXwDwoyinmeOY9eKyh6aY72xJh7noLBBq1N0bWi1e2i+83txOCg4yV2oVXhB
o8pYEJ8LT3el6Smxol3C1oFMVdwPgc0vTl25XucMcG/ALE/KNY6pqC2AQ6R2ERlV
gPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeulmCpGSynXNcpZ/06+vofGi/2MlpQZNhH
Ao8eayMp6FcvNucIpUndo1X8dKMv3Y26ZQIDAQAB
-----END RSA PUBLIC KEY-----';

        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPublicKey());
        $this->assertFalse($rsa->getPrivateKey());
    }

    public function testPubKey2()
    {
        $rsa = new Crypt_RSA();

        $key = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS
+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS
EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n
oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v
Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu
lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26
ZQIDAQAB
-----END PUBLIC KEY-----';

        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPublicKey());
        $this->assertFalse($rsa->getPrivateKey());
    }

    public function testPubKeyPssWithoutParams()
    {
        $rsa = new Crypt_RSA();

        // extracted from a SubjectPublicKeyInfo of a CSR created by OpenSSL
        $key = '-----BEGIN PUBLIC KEY-----
MIIBIDALBgkqhkiG9w0BAQoDggEPADCCAQoCggEBANHPPf5tjTmEHtQvzi6+rItj
G3OUvh6Nihc9bXSu0xNFjl/9TdyIXstRUG/Lh07isHgZFEfXn4pmm/iZIQh09ACg
TjEau8rpcLB0BS9dDgTh8hvgkbdxWR2UPxk34bFcdgIplckslAfB4+/ebL+ObvUa
W3sZosTq3D6/qh0fujGZg/EKLJcNCHI27XMiAT5yWztSjHWwQm7LBwJ5uKlFLEDC
Z/+LIV/vPEIMfE6lA/+OnLKwVFB540eXQPuWar1ARHXN8PpiCqJHanddYMA5l/Cw
5R7kJ+CBoHzaPePXjB9V1bfzEBzBHb2ddiSjum+qtLWuH0Q7B8gPX9EjxIwuCzMC
AwEAAQ==
-----END PUBLIC KEY-----';

        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPublicKey());
        $this->assertFalse($rsa->getPrivateKey());
    }

    public function testPrivateKeyPssWithoutParams()
    {
        $rsa = new Crypt_RSA();

        $key = '-----BEGIN PRIVATE KEY-----
MIIEugIBADALBgkqhkiG9w0BAQoEggSmMIIEogIBAAKCAQEA0c89/m2NOYQe1C/O
Lr6si2Mbc5S+Ho2KFz1tdK7TE0WOX/1N3Ihey1FQb8uHTuKweBkUR9efimab+Jkh
CHT0AKBOMRq7yulwsHQFL10OBOHyG+CRt3FZHZQ/GTfhsVx2AimVySyUB8Hj795s
v45u9RpbexmixOrcPr+qHR+6MZmD8Qoslw0IcjbtcyIBPnJbO1KMdbBCbssHAnm4
qUUsQMJn/4shX+88Qgx8TqUD/46csrBUUHnjR5dA+5ZqvUBEdc3w+mIKokdqd11g
wDmX8LDlHuQn4IGgfNo949eMH1XVt/MQHMEdvZ12JKO6b6q0ta4fRDsHyA9f0SPE
jC4LMwIDAQABAoIBAFPuTMWAO7Obh92oNhn7CvlDr1KgWSHNy0UavLOl0ChwddEu
erxTDWDWaZAfYkSLaL7SgYtv1ZG/FHvxfgZtCsNJXZ5FLISyt/LOpthYqGgJnxnJ
z2EMBfNQP6Gt+ipCa67XxeTRYXJs/OsTFnvW1cpVPe1TxwpxTaQIdlvqOkjmgCci
TRzH+Acj8unWDHAJpQkCOvmi+25sE0BMQYWnsfMSzm63Yk3SeZLIJKqoUdZhYMZU
6FK2DMDNR4TZps7s50MFlZfUUJfzgb4Hb4miiKzLPhf4q7rxS4VzrvUQ/81ySCwi
1LaSw5HoH1YMDT6rwcHMwHhzhu8X2CKlNIrri8ECgYEA7aiZAxmlY28LWcXHqqhZ
Yky76vLy/mbs0TfAVK2pSqyFhaGZe5daAJSIrVcZEEgAwR6/ZLITTWBuGdsHw6vF
GtSvkElLhopmQEs73kKqeBFLhpTqYXYVW0txi3jdWElie8fZa/Oa/sFLEeNsibQu
fbVWWGakf9458FDuR0i2k+ECgYEA4gBu2u6xkJzqOzOjBg5tNhxmzcPyt4Ds3ryA
e+C5hVCotd1EX6HZRPYjLEys0yUhiXDAn7ViEdtiXt9RYfpK+OKLGeTZ7pMCyZW+
Yhc0i2XYqWSKUH3iNonp8B0JSkfEQBY2KlA7b5YZQZkr/Ml/WtoKeicHLBcdVxqa
t7krQZMCgYBMU7GQxVPQs4E5u8N8k8ThRTO1KYHRIs08BGPIzl1oli/r0xKwFtPZ
C9s5kJeEGxvi6jUd6fM5DpdNxoKf3TLYgyY/eMrA0wIz8/WuVErbdPKErp733izN
vVUiLhcom6j9iBnUCdDlsL6jaB8burqTtQGeMpjyWDTTcaqVSk0ZAQKBgCqc1EoZ
eYd/3rZc7R8mNzddsZCYorow5/izaDJzU+esJrNrzgmOFc5n7ofayTdip+knRlqW
s7AUQn8K8mhb7ijxZjLysJjIRV1HC8epAnJKOMjvuRimM7H+3Qo2H1tPHtTKm1nt
GNfYYFi7Dc0zHP0/YXxYwYRxs0mKLaP4mQxbAoGARHngPhGC0yM5KqxNrkHPVjLq
CHQy+e9GTPXtDLC3D7HAYyyzKqy4mdBDzMeLqA3a+iT2PXjn4w5zOEW8GAcRYRtG
3EyvclPmWtmCpU5xqD8ieFtQhMeW/XzJHjTXlcncz0PCkGVoQiuRvXWNAukNPg0D
BocC2CO6SNi4Qjr3NlM=
-----END PRIVATE KEY-----';

        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPublicKey());
        $this->assertIsString($rsa->getPrivateKey());
    }

    public function testSSHPubKey()
    {
        $rsa = new Crypt_RSA();

        $key = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4e' .
               'CZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMS' .
               'GkVb1/3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZw== ' .
               'phpseclib-generated-key';

        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPublicKey());
        $this->assertFalse($rsa->getPrivateKey());
    }


    public function testSSHPubKeyFingerprint()
    {
        $rsa = new Crypt_RSA();
        $key = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD9K+ebJRMN10kGanhi6kDz6EYFqZttZWZh0'.
              'YoEbIbbere9N2Yvfc7oIoCTHYowhXND9WSJaIs1E4bx0085CZnofWaqf4NbZTzAh18iZup08ec'.
              'COB5gJVS1efpgVSviDF2L7jxMsBVoOBfqsmA8m0RwDDVezyWvw4y+STSuVzu2jI8EfwN7ZFGC6'.
              'Yo8m/Z94qIGzqPYGKJLuCeidB0TnUE0ZtzOJTiOc/WoTm/NOpCdfQZEJggd1MOTi+QUnqRu4Wu'.
              'b6wYtY/q/WtUFr3nK+x0lgOtokhnJfRR/6fnmC1CztPnIT4BWK81VGKWONAxuhMyQ5XChyu6S9'.
              'mWG5tUlUI/5';
        $this->assertTrue($rsa->loadKey($key));
        $this->assertSame($rsa->getPublicKeyFingerprint('md5'), 'bd:2c:2f:31:b9:ef:b8:f8:ad:fc:40:a6:94:4f:28:82');
        $this->assertSame($rsa->getPublicKeyFingerprint('sha256'), 'N9sV2uSNZEe8TITODku0pRI27l+Zk0IY0TrRTw3ozwM');
    }

    public function testSetPrivate()
    {
        $rsa = new Crypt_RSA();

        $key = '-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA61BjmfXGEvWmegnBGSuS+rU9soUg2FnODva32D1AqhwdziwHINFa
D1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBSEVCgJjtHAGZIm5GL/KA86KDp/CwDFMSw
luowcXwDwoyinmeOY9eKyh6aY72xJh7noLBBq1N0bWi1e2i+83txOCg4yV2oVXhB
o8pYEJ8LT3el6Smxol3C1oFMVdwPgc0vTl25XucMcG/ALE/KNY6pqC2AQ6R2ERlV
gPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeulmCpGSynXNcpZ/06+vofGi/2MlpQZNhH
Ao8eayMp6FcvNucIpUndo1X8dKMv3Y26ZQIDAQAB
-----END RSA PUBLIC KEY-----';

        $this->assertTrue($rsa->loadKey($key));
        $this->assertTrue($rsa->setPrivateKey());
        $this->assertGreaterThanOrEqual(1, strlen("$rsa"));
        $this->assertFalse($rsa->getPublicKey());
    }

    /**
     * make phpseclib generated XML keys be unsigned. this may need to be reverted
     * if it is later learned that XML keys are, in fact, supposed to be signed
     * @group github468
     */
    public function testUnsignedXML()
    {
        $rsa = new Crypt_RSA();

        $key = '<RSAKeyValue>
  <Modulus>v5OxcEgxPUfa701NpxnScCmlRkbwSGBiTWobHkIWZEB+AlRTHaVoZg/D8l6YzR7VdQidG6gF+nuUMjY75dBXgY/XcyVq0Hccf1jTfgARuNuq4GGG3hnCJVi2QsOgcf9R7TeXn+p1RKIhjQoWCiEQeEBTotNbJhcabNcPGSEJw+s=</Modulus>
  <Exponent>AQAB</Exponent>
</RSAKeyValue>';

        $rsa->loadKey($key);
        $rsa->setPublicKey();
        $newkey = $rsa->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_XML);

        $this->assertSame(preg_replace('#\s#', '', $key), preg_replace('#\s#', '', $newkey));
    }

    /**
     * @group github468
     */
    public function testSignedPKCS1()
    {
        $rsa = new Crypt_RSA();

        $key = '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/k7FwSDE9R9rvTU2nGdJwKaVG
RvBIYGJNahseQhZkQH4CVFMdpWhmD8PyXpjNHtV1CJ0bqAX6e5QyNjvl0FeBj9dz
JWrQdxx/WNN+ABG426rgYYbeGcIlWLZCw6Bx/1HtN5ef6nVEoiGNChYKIRB4QFOi
01smFxps1w8ZIQnD6wIDAQAB
-----END PUBLIC KEY-----';

        $rsa->loadKey($key);
        $rsa->setPublicKey();
        $newkey = $rsa->getPublicKey();

        $this->assertSame(preg_replace('#\s#', '', $key), preg_replace('#\s#', '', $newkey));
    }

    /**
     * @group github861
     */
    public function testPKCS8Only()
    {
        $rsa = new Crypt_RSA();

        $key = '-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKB0yPMAbUHKqJxP
5sjG9AOrQSAYNDc34NsnZ1tsi7fZ9lHlBaKZ6gjm2U9q+/qCKv2BuGINxWo2CMJp
DHNY0QTt7hThr3B4U62z1CWWGnfLhFtHKH6jNYYOGc4x0jgT88uSrKFvUOLhjkjW
bURmJMpN+OjLJuZQZ7uwoqtT3IEDAgMBAAECgYBaElS/fEzYst/Fp2DA8lYGPTs4
vf2JxbdWrp7phlxEH3mTbUGljkr/Jj90wnSiojFpz0jm2h4oyh5Oq9OOaJwkCYcu
2lcHJvFlhR2XEJpd1bHHcvDwZHdUjSpnO8kvwQtjuTnho2ntRzAA4wIJVSd7Tynj
0IFEKmzhSKIvIIeN8QJBANLa10R1vs+YqpLdpAuc6Z9GYhHuh1TysBPw2xNtw3Xf
tGPx4/53eQ0RwiHdw9Opgt8CBHErD6KzziflfxUrIXkCQQDCz4t01qYWT43kxS6k
TcnZb/obho6akGc8C1hSxFIIGUa9hAhMpY2W6GXeGpv5TZtEJZIJE1VHTLvcLSGm
ILNbAkEAgq9mWqULxYket3Yt1ZDEb5Zk9C49rJXaMhHHBoyyZ51mJcfngnE0Erid
9PWJCOf4GBYdALMqtrHwpWOlV05rKQJAd6Tz50w1MRqm8MvRe4Ny5qIJH4Kibncl
kBD/q8V7BBJSCe7fEgPTU81jUudQx+pL46yXZg+DnoiYD/9/3QHUZQJBAMBiKiZ7
qMnD/pkHR/NFcYSYShUJS0cHyryVl7/eCclsQlZTRdnVTtKF9xPGTQC8fK0G7BDN
Z2sKniRCcDT1ZP4=
-----END PRIVATE KEY-----';

        $result = $rsa->loadKey($key, CRYPT_RSA_PRIVATE_FORMAT_PKCS8);

        $this->assertTrue($result);
    }

    /**
     * @group github960
     */
    public function testSetLoad()
    {
        $key = 'PuTTY-User-Key-File-2: ssh-rsa
Encryption: aes256-cbc
Comment: phpseclib-generated-key
Public-Lines: 4
AAAAB3NzaC1yc2EAAAADAQABAAAAgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4
eCZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RK
NUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDy
R4e9T04ZZw==
Private-Lines: 8
llx04QMegql0/nE5RvcJSrGrodxt6ytuv/JX2caeZBUyQwQc2WBNYagLHyHPM9jI
9OUWz59FLhjFXZMDNMoUXxVmjwQpOAaVPYNxxFM9AF6/NXFji64K7huD9n4A+kLn
sHwMLWPR5a/tZA0r05DZNz9ULA3mQu7Hz4EQ8ifu3uTPJuTmL51x6RmudYKysb20
fM8VzC3ukvzzRh0pujUVTr/yQdmciASVFnZlt4xQy+ZEOVUAOfwjd//AFfXTvk6x
7A45rNlU/uicHwLgoY1APvRHCFxw7F+uVW5L4mSX7NNzqBKkZ+1qpQTAfQvIfEIb
444+CXsgIyOpqt6VxJH2u6elAtE1wau3YaFR8Alm8m97rFYzRi3oDP5NZYkTCWSV
EOpSeghXSs7IilJu8I6/sB1w5dakdeBSFkIynrlFXkO0uUw+QJJWjxY8SypzgIuP
DzduF6XsQrCyo6dnIpGQCQ==
Private-MAC: 35134b7434bf828b21404099861d455e660e8740';

        $rsa = new Crypt_RSA();
        $rsa->setPrivateKey($key);
        $rsa->loadKey($key);

        $rsa = new Crypt_RSA();
        $rsa->loadKey($key);
        $rsa->setPrivateKey();
        $rsa->loadKey($rsa);
    }

    /**
     * @group github980
     */
    public function testZeroComponents()
    {
        $key = '-----BEGIN RSA PRIVATE KEY-----
MIGaAgEAAkEAt5yrcHAAjhglnCEn6yecMWPeUXcMyo0+itXrLlkpcKIIyqPw546b
GThhlb1ppX1ySX/OUA4jSakHekNP5eWPawIBAAJAW6/aVD05qbsZHMvZuS2Aa5Fp
NNj0BDlf38hOtkhDzz/hkYb+EBYLLvldhgsD0OvRNy8yhz7EjaUqLCB0juIN4QIB
AAIBAAIBAAIBAAIBAA==
-----END RSA PRIVATE KEY-----';

        $rsa = new Crypt_RSA();
        $rsa->loadKey($key);
        $rsa->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
        $rsa->setHash('md5');
        $rsa->setMGFHash('md5');

        $rsa->sign('zzzz');
    }

    public function testGoodBad()
    {
        $rsa = new Crypt_RSA();

        $key = '-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA61BjmfXGEvWmegnBGSuS+rU9soUg2FnODva32D1AqhwdziwHINFa
D1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBSEVCgJjtHAGZIm5GL/KA86KDp/CwDFMSw
luowcXwDwoyinmeOY9eKyh6aY72xJh7noLBBq1N0bWi1e2i+83txOCg4yV2oVXhB
o8pYEJ8LT3el6Smxol3C1oFMVdwPgc0vTl25XucMcG/ALE/KNY6pqC2AQ6R2ERlV
gPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeulmCpGSynXNcpZ/06+vofGi/2MlpQZNhH
Ao8eayMp6FcvNucIpUndo1X8dKMv3Y26ZQIDAQAB
-----END RSA PUBLIC KEY-----';

        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPublicKey());
        $this->assertFalse($rsa->loadKey('zzz'));
        $this->assertFalse($rsa->getPublicKey());
    }

    public function testOpenSSHPrivate()
    {
        $key = '-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA0vP034Ay2qMBEjZVcWHCzkhD0tUgHgUyLuUtrPKEZU06wQ/Wchki
QXbD0dgAxlZoQ/ZR0N3W4Y0qZCKguJrGftsjyyciKcjmPQXVvleLFH0FDuQTjvJKMiE4Q0
pCWHabD9kllLWVOYJ/iwBanBpUn4/dAQaGFjLQjRLIARTI6NZGAxmIaBb+cI8sc+qzB0Wf
bMGM0+8AO5yeaZnRJtdGAh9AHDOHT+V6rubdYVsoYBIHdlAnzcv+ESUhQYYJOyW/q2od6L
8IF5+WVPQiz8nNe3znjRck+T/KSY6X8fS/VyfmQDjkmSMUk3j3uB61qNzUdRNmTKgTTrMf
JY5bM+jDcUocH5OpXhYONJ4dpP1QDqFge4+ZaCn5Mz89BjhkJUeOMWlaB8Kqvz7BzilCmD
+qv4TossTqcZIGsgdEIG7HSt9lVsz0medt/69+YmkuhikSfZ0RAAO+JUZ5gXTGwFm0BFpJ
WNLxJeOsgA6WQmUQGRK3rY1wg2LMNK4u0Vyo/LvLAAAFiB5Yhp8eWIafAAAAB3NzaC1yc2
EAAAGBANLz9N+AMtqjARI2VXFhws5IQ9LVIB4FMi7lLazyhGVNOsEP1nIZIkF2w9HYAMZW
aEP2UdDd1uGNKmQioLiaxn7bI8snIinI5j0F1b5XixR9BQ7kE47ySjIhOENKQlh2mw/ZJZ
S1lTmCf4sAWpwaVJ+P3QEGhhYy0I0SyAEUyOjWRgMZiGgW/nCPLHPqswdFn2zBjNPvADuc
nmmZ0SbXRgIfQBwzh0/leq7m3WFbKGASB3ZQJ83L/hElIUGGCTslv6tqHei/CBefllT0Is
/JzXt8540XJPk/ykmOl/H0v1cn5kA45JkjFJN497getajc1HUTZkyoE06zHyWOWzPow3FK
HB+TqV4WDjSeHaT9UA6hYHuPmWgp+TM/PQY4ZCVHjjFpWgfCqr8+wc4pQpg/qr+E6LLE6n
GSBrIHRCBux0rfZVbM9Jnnbf+vfmJpLoYpEn2dEQADviVGeYF0xsBZtARaSVjS8SXjrIAO
lkJlEBkSt62NcINizDSuLtFcqPy7ywAAAAMBAAEAAAGBALG4v8tv6OgTvfpG9jMAhqtdbG
56CYXhIMcrYxC6fFoP93jhS+xySk7WrODkVrrB3zOqmIEb9EWvtVAJcFg2ZRZIrt4fSQPk
8jvk549ll5GaRiGmeufKLkIPhKQEMuLugXKXobaoSGDcFXHYyX2MHVEUVb/gbCTViKfhc8
idZynqI6/G2gm/nXrc1DmQOGXe/RIV+fwu9YZDS55x7SgI4z00cMGRk+T20yX47/duYhSV
+91saCxUOObe3iaisrI2+LzNJx5AbGJS5fWohc1psvkXW5buysOUgKiPOoaoYmMaE4wW2j
rJLEjHD1iiM1ZhlTRJWI5qKn9q8ehE7ovUBGKkVl/htR3VroTjSzpEfgQXGi2G7lavhF0m
acExXJ8ALLQRduBA4lJNTdXh/I4LfI4bliu/oWCaGTp0aJgWEN+Mz3DpSqMhPKIJ4YswCd
vNRAZ2a0vKJIqbzVD42aZhud8FUMy5bkKtTpCKVYQphwOVF3mgdvtmkRGSoljDyre10QAA
AMARVhG4dCOJD02/oM3OVxP1eR6dHvtvJXC7zDyuq0R9MCrJl1PlNFQalV3fcSc1e7Kq1w
iMsauVCN+2+QHNl99c2LMbfj0YKtWk6vLqOZnWtkvRol5T1xNHQ+aAh2Wbn5CMOLYVLoJS
3ceZp0x4KINj2soqrpP3GKwgQ0uuQZkbo1G7er/8oswOeFRCu9psjzF1cYxKTZL+pRAbJl
dO/UzciVgiKW2mkLA1E2ktuvlNtIfuhh61vczs9uNJioLb8s4AAADBAO7nzGt+98HyPJ6b
/PRIopYtZVWkCu6qoI9JK2Ohq2mgu09+ZfsTas5ro356P2uuKI/5U2TAKafSaOM3r71jIh
eZhvMynMUPb0EAJVVJv1pcm9xn+/Qk9ZE9ThnMdvVReGJcGBH0wLleVXNQ6LloazFE9Bpu
r6DsF8nOjhs2isonhCpsPfHH5Msw3RUA3ZoiY1HPb2/kZ9ovAdbOGHeJjpl3ONHqSc5qZI
zSVLiqzewARwPGvWqna4vuDV67N5te8wAAAMEA4gwhzND1exC3Qx0TWmV7DwdxkeTPk3Qb
jtOtyLV4f3LWgd2kom5+uB+oKHrZPvtPKxtu361gTKqPSaDFyTezvsq5RdfGEp3g82n3J3
r14GFuIepTGRZkU2i8dyEWk5V/RFMCwWhJZsAqdqM91TcOU4R6cnwRgH91qGHLrPRaK2NR
SGEfpUzSl3qTM8KC7tcGi1QucKzOoeyTICMJLwXKUtmbU+aO2cl/YGsSRmKzSP9qeFKVKd
Vyaqr/WTPzxdXJAAAADHJvb3RAdmFncmFudAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----';

        $rsa = new Crypt_RSA();
        $this->assertTrue($rsa->loadKey($key));

        $key = $rsa->getPrivateKey(CRYPT_RSA_PRIVATE_FORMAT_OPENSSH);
        $rsa = new Crypt_RSA();
        $this->assertTrue($rsa->loadKey($key));

        $sig = $rsa->sign('zzz');

        $key = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDS8/TfgDLaowESNlVxYcLOSEPS1SAeBTIu5S2s8oRlTTrBD9ZyGSJBdsPR2ADGVmhD9lHQ3dbhjSpkIqC4msZ+2yPLJyIpyOY9BdW+V4sUfQUO5BOO8koyIThDSkJYdpsP2SWUtZU5gn+LAFqcGlSfj90BBoYWMtCNEsgBFMjo1kYDGYhoFv5wjyxz6rMHRZ9swYzT7wA7nJ5pmdEm10YCH0AcM4dP5Xqu5t1hWyhgEgd2UCfNy/4RJSFBhgk7Jb+rah3ovwgXn5ZU9CLPyc17fOeNFyT5P8pJjpfx9L9XJ+ZAOOSZIxSTePe4HrWo3NR1E2ZMqBNOsx8ljlsz6MNxShwfk6leFg40nh2k/VAOoWB7j5loKfkzPz0GOGQlR44xaVoHwqq/PsHOKUKYP6q/hOiyxOpxkgayB0QgbsdK32VWzPSZ523/r35iaS6GKRJ9nREAA74lRnmBdMbAWbQEWklY0vEl46yADpZCZRAZEretjXCDYsw0ri7RXKj8u8s= root@vagrant';

        $rsa = new Crypt_RSA();
        $this->assertTrue($rsa->loadKey($key));

        $this->assertTrue($rsa->verify('zzz', $sig));
    }

    public function testPuTTYV3NoPW()
    {
        $key = 'PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20220216
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCJ39DLYw81oZmBMeRze+Plu0p8+kJezer4
mRpltRoqpZ0yRnyb5k0FtXrDeYL9IyCceOTsse/qks3CtVWQ2q7C2tqyezmk8mDf
aKXqnaSG3hHZo7vJcy76J7NNB6Mz2BxF9RGvb+sylEKdWOJdgmYC6dzyvpg/0qs6
yNPQGA5QOOzy2AstxnsujDl16I0GGsjw7ybc5844Hq4VhIQaft2Yd35UqGt5G1hs
nIZu1cLO/F+8xs+0xEY04FvJRNAoJGlVc8oPx7slU7vF5m22AmBqrhkljbid72OR
oXpI+4c7zc0dYZBIMoAEIJKTbliQE1WV0lYiXkS9RY3UjUyPLho9
Private-Lines: 14
AAABAQCI4IliEeMcpGVILOcXe2yCO1E1CCLyCc53pU/en0/t/OM18WJuR9I5k7Tf
8XeIpeIPVbo3/mMn5zydS/c5ytDrI+kwfkN5LSPdSABIDt8zAa6I+hNJaK+/q8BG
/gkZRDi1fxpiqGLAoQ4NNhvtJ7Lsu44d8/gkjJpvzsbx9Z/oJVK8ID10Wiiz9R7u
WPCOJbrETGU1LaY4N0hwhbqD28xtX4ypBh+HQ9umCqOMopeqVhebMolAZ62K5V+N
SbdN1JFk2FPQxMv3v4ApDW48AcJ1dNgO6euncaySLaQv3tnxYVjKVaf3JO0ALzoq
zsR2uj5bJUvhSapj9uWdDJTurGzFAAAAgQDY5t/F2Ruoa5wtF/XTiIxFpb//xQ+2
JhQOWd1fZZ+oMclqNS5E45E11TWnKthgr5NN4UB6TH4rtUETjsypD3w2PYZamTD1
QzeoOS0xRxjKfQu08ApDV94mx9LfX6Xi2IqTW0pC+IbBx8AUnK7J7scva8TYn7Qu
1QLSY4/tn3BBBwAAAIEAorolHJnR+w5FajTc8VeqN5E9bfc39Mr+2lQcqtARJGAM
2jLhN3ZWGIboG3Ttqcbfuicv/WzFe+gGRA8awvMS4v2C5/knZl4Vq859KCP7JOeW
63+5mLw5OKZOzWkguMu8+IfkUtIMv1JFuCU2eRL5elUthKlK6WFcMejuygNTrZsA
AACARP7yi23FNxAqHcgbx5MlrLYbMSjxp5yT+1XeNVTSpM/dvDVsy+8ETi/c1870
UfAzuIHQl2fu6NdtPBQUoqWKgBRtp46J/BoWF3Ty6klz+FAP2of4gojYvqa87H+6
dW7G8+QXxXM704cxjbBQAApItfVw3upWPrYP9FDy7xvtYRY=
Private-MAC: 7979eb6f604fb3e0bd191295479517f641598649167835402c6cbfde6cbf21ef';

        $rsa = new Crypt_RSA();
        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPublicKey());
        $this->assertIsString($rsa->getPrivateKey());
    }

    public function testPuTTYV3PW()
    {
        if (!function_exists('sodium_crypto_pwhash')) {
            self::markTestSkipped('sodium_crypto_pwhash() function is not available.');
        }

        $key = 'PuTTY-User-Key-File-3: ssh-rsa
Encryption: aes256-cbc
Comment: rsa-key-20220216
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCJ39DLYw81oZmBMeRze+Plu0p8+kJezer4
mRpltRoqpZ0yRnyb5k0FtXrDeYL9IyCceOTsse/qks3CtVWQ2q7C2tqyezmk8mDf
aKXqnaSG3hHZo7vJcy76J7NNB6Mz2BxF9RGvb+sylEKdWOJdgmYC6dzyvpg/0qs6
yNPQGA5QOOzy2AstxnsujDl16I0GGsjw7ybc5844Hq4VhIQaft2Yd35UqGt5G1hs
nIZu1cLO/F+8xs+0xEY04FvJRNAoJGlVc8oPx7slU7vF5m22AmBqrhkljbid72OR
oXpI+4c7zc0dYZBIMoAEIJKTbliQE1WV0lYiXkS9RY3UjUyPLho9
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 13
Argon2-Parallelism: 1
Argon2-Salt: d9bfa07d14a450a26ada4eb5d30c4dae
Private-Lines: 14
L3TUmo97jnxJVYIScxzPIaq19/yNQ5HDQKGSTz4vqUrQR3wXQEyhzxlN2mm5zZtT
pst7K61P0awtjs4kHUfsKxXh/upv7ndS9u9G7cnnBfP5mjs0wAE2VaghbP4UXprH
/MQC9Dr13Iuydv5Oih+PLpkvM3DbY5t+nrIWy/29yDLYe/QjLvy346Gz3pnLmCfb
hbEFfjefdppa+6QZ+qU6ai/NMAM/Q5OxjRlIo1brrKJNvMrbzP7irZ4+Ao2Or/hX
nb2ZZLY0eUotD8iFuOk2EjjqP9iakag1OHdvdy6EcPzkIObN5YeZGz9/hRDFr9Ml
xNxdaw5c1BhqU5pm0B0HUDqW5kmYTiugUKQiGr0+1ckliUt6jsb7YImnqJIgL7PS
vKcqNvz95u4on77gHPl2JdsXxuz6jOkDwc9jvsJCtIMJ8qhAVXGS7WaH2aF9ty7B
4E+f2yIbsRr0RFCZoTTjTmhtYsVd7DYo0Jftya3Sh/lVO1MLo1z8em0MFJdR683N
tRDA2lbRPOdKYaiKdyp5bAsl4fqPR1e2GR9ybalPn/XSFDRtDfdMr7hyQboBR7uC
X3nYsh5OiXakUSr2ST41pP27s8F48590M6xWb9LGFJA+JqmAZ5rxPTxFYjkz27y9
Yvlq6lvM+XsUREPrxhWrHya4Jyp4WtyVtJXDg626hoZBSEtcOY/mbPfwVFnoU9vz
V8TI/YU837mUceEJlEQEbT+bFJfh0W5jzAYx2xX6uPnDkodBMK2p6QS3ZKib0NJ7
W+jQr9TT40H0agZhtAmPKaLGxtgdpUps1CDPV+8Y/pBf28CsI2DjFaOYopZXcW9s
vCIjXopt4wAKbXiLyb5JXzFfB7CVron48NHB7wzuwvnUoYa/4dbjeEos+1y72xoP
Private-MAC: d26baf87446604974287b682ed9e0c00ce54e460e1cb719953a81291147b3c59
';

        $rsa = new Crypt_RSA();
        $rsa->setPassword('demo');
        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPublicKey());
        $this->assertIsString($rsa->getPrivateKey());
    }

    public function testOpenSSHEncrypted()
    {
        if (PHP_INT_SIZE === 4) {
            self::markTestSkipped('bcrypt is far too slow to be practical on 32-bit versions of PHP');
        }

        $key = '-----BEGIN OPENSSH PRIVATE KEY-----
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
LrIZULwMa4nI4Y+RkFftEponSYw=
-----END OPENSSH PRIVATE KEY-----
';

        $rsa = new Crypt_RSA();
        $rsa->setPassword('test');
        $this->assertTrue($rsa->loadKey($key));
        $this->assertIsString($rsa->getPublicKey());
        $this->assertIsString($rsa->getPrivateKey());
    }
}
