<?php
/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2013 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */
echo "requiring crypt rsa\r\n";
require_once 'Crypt/RSA.php' ;
require_once 'Math/BigInteger.php';

class Unit_Crypt_RSA_LoadKeyTest extends PhpseclibTestCase
{
    public function testLoadPKCS8PrivateKey()
    {
/*
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
echo "VALUE OF LOADKEY = ";
var_dump($rsa->loadKey($key));
echo "\r\n";

        $this->assertTrue($rsa->loadKey($key));
        $this->assertInternalType('string', $rsa->getPrivateKey());
*/
include('Crypt/DES.php');

$des = new Crypt_DES(CRYPT_MODE_CBC);
$des->setKey(pack('H*', '0aeaf44a2ba7c61c'));
$des->setIV(pack('H*', 'a3b5f0dc311ef07b'));

//$des->disablePadding();
//$des->setPreferredEngine(CRYPT_ENGINE_INTERNAL);
echo "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\r\n";
echo gettype($des->decrypt(pack('H*', 'ba1ae5bde4b5c3e6cb85418479291f355212c2893e641351a42f530229ebe85865eb8e93bf043de86b609fd07b3c0945dc81a03e75a0ec6a5821367d9e567fa322ffd348b8fcaa41c70fda8b84adc3007032da031f42d0eb77ef2a06d12ea139981ac6ac2709d198287812edc614bf8d242ce2664ce2651c96dab5f5c7a1cac7707902049d6af3002903529540866caa6c81501bb06eb7c5c290bd77f47aef85f10962695ef53add5359445614bdded81160ab7527a579bf7da74567d64c48e78eb73d7bab82cffb18f88e48b49d5f8e031123fd97b9577a70b881bb93f0fd314110f31ab07997d1c7a15dca31714e0d64cc9cb729d67ba10343937cf4b6cb34fdcc982a1e254a5a0714509e6e0de9557e7b260e19e1e36f29d060456e7887d3ba91102f64abbf14a903482b26e9e23438b0fb3ae337589bf5722d6b40633f103402872dc9cfc264cfaff5e5266a31f2b95086e4904caf04fa50eb4ce2a9c9dae28cdde517ea60c94b948fa1daf132cc70e3b0a9cae9062838486628079ea08c03b4c9313db823dd05a923cb18b792c9f9d44ae2806336a4630d71577092927fc7e0c40413b46aecb7b7dc6a33a2caf29c0d70e4f51163bed7acd8efd2d549abdce3db7e5f131cdd76accff1b9c50803d45069ea9127b20e498534c6fe287a63f0d00fccf7a6b8c2dea29cae92f8340f4a048fc81758885e5adf98dff308a6c1b843841aac1c1c10c73f24996e12f65cb4a919c2bf3419756e8d591beda75136aea02ebb41bd3e7e7cd372f3a230d01b1cc8aa922aece1a9c75f7dcc28bda047fddda7c71af6185659767332493614af6c0bfa2b77d17a993b6f4e23920f3a621216fde2e4f15ea06121bb2b19709451dd1040de6cd9d996d8c7d2337e4a792bf6af00c6cc2d7e41fdcc847188643aa8430b99133339c871da7c26ad01b65ddac8da1567a0834af671aeda799919163dd9b836172459cbf3682e3804a1eeb12558ed98b3b9dc5c02a7695dd692417e243bff0941ebf90fe1e807b9a84be0b9b4c2552607cd13f7ed7248b6571dcb04c871363eb7a8f29a6c84049eba2e65280f8ee0b7fbc35126e14fa39a1a5719f8c6469549cf392ab86249ce830287f22cdba18e148150ab997be56996108597a63439156e96150dfface9c3dfb49c15a197fea9fd92b114d4b08d748aca08cc2c86c3689ef249a2a5d3f8df867ff7db95537cf10faada343972a77dea156320a6bd8953a3550256bb379d60ec993c5632089fb4af098c96926befe242c1d541e5dcd16a61bf58b88654683cad8ff34c70a30b2ce684a2b459d8dda60cda2284cc4c7fc27727d00f9f3522800b5a6a518a34eaddd85a26e4e5400de3ef4dbe6c835b954337dca45ae32252d587ed9c7a45f424cf38a616cca479a6e6f0a38df62f52f70ccb472509fd31de3cfa2d97f917373cc5b666a6c7b93a73abb032c2361f9295c60ecec6a0499ab84e0bd2788f53af896fe3c74b24708271828b7b2992f67865085bae1db8bbcc8ede75c238f702945b54a3fa4bcaab72cc20490c960cea18a03a26a495c473f9d551f916a57868aabbd07e9d349e376cb5513e1b45e418a9e4fee4ffa288b064cf51de783c77b2f83b964638ad7e178bd06db0185feaa19c82d666ea76dcb2796807b556c95543919a96cd9d738823d76e12a05434388ef55499367ffc87f56c61e001c6bc996910d59ad32e7ff39905')));

    }
/*
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
*/
}
