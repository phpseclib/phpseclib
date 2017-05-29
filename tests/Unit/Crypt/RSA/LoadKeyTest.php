<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2013 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'Crypt/RSA.php' ;

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
        $this->assertInternalType('string', $rsa->getPrivateKey());
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
        $this->assertInternalType('string', $rsa->getPrivateKey());
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
        $this->assertInternalType('string', $rsa->getPrivateKey());
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
        $this->assertInternalType('string', $rsa->getPrivateKey());
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
        $this->assertInternalType('string', $rsa->getPrivateKey());
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
        $this->assertInternalType('string', $rsa->getPrivateKey());
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
        $this->assertInternalType('string', $key);

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
        $this->assertInternalType('string', $rsa->getPublicKey());
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
        $this->assertInternalType('string', $rsa->getPublicKey());
        $this->assertFalse($rsa->getPrivateKey());
    }

    public function testSSHPubKey()
    {
        $rsa = new Crypt_RSA();

        $key = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4e' .
               'CZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMS' .
               'GkVb1/3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZw== ' .
               'phpseclib-generated-key';

        $this->assertTrue($rsa->loadKey($key));
        $this->assertInternalType('string', $rsa->getPublicKey());
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
        $this->assertInternalType('string', $rsa->getPublicKey());
        $this->assertFalse($rsa->loadKey('zzz'));
        $this->assertFalse($rsa->getPublicKey());
    }
}
