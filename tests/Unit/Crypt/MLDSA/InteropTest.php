<?php

/**
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\MLDSA;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\{MLDSA, PublicKeyLoader};
use phpseclib4\Crypt\MLDSA\Formats\Keys\PKCS8;
use phpseclib4\Crypt\MLDSA\{PrivateKey, PublicKey};

/**
 * Interoperability with keys and signatures made by the OpenSSL command line tool (OpenSSL 4.0.3):
 *
 *   openssl genpkey -algorithm ML-DSA-44 -out cli-key-ML-DSA-44.pem
 *   openssl pkey -in cli-key-ML-DSA-44.pem -pubout -out cli-key-ML-DSA-44-pub.pem
 *   openssl pkeyutl -sign -inkey cli-key-ML-DSA-44.pem -rawin -in msg.bin -out cli-key-ML-DSA-44.sig
 *
 * genpkey writes the both CHOICE of RFC 9881 (seed and expanded key)
 */
class InteropTest extends TestCase
{
    private const PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----';

    private const PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----
MIIFMjALBglghkgBZQMEAxEDggUhALx705mTygOz0kahvA75vsAiGYgNievSDJCc
2MlrQA3IxU31sbTbBGyaHNJ3no0Bjj6/Kl8VR8ETk/ldBCeljXSXGzLDpqkDlZ8M
wKB2Nt+3uneIOAi1Q/PKBUWdYesVPTcYsUZBmPFeN9amfcPwjhSACteMRYQyHatW
gFHL9IaFmE0LqLS/9W92F2KaQSWg9GhutGaGjweERXhFYXRbtC5vHRNSOCr0R6SN
BWHccpOUDJrPzvb/7RdTFrGwjIcv+YIv9URghhVLCcai0047sYNds0KxdZpnUHxF
8cctjGBL9dOusdeO7J5wAMNPebumoVIROxiC6ukEfn0JlSrp7iD0rRKtYSpjnSXW
TzDNOLk8a7tU6iK1z7DemyU7QOJuANK75C+vetZUyck2PF+LwmDWnkKyND97iNwi
w2sAHFh1QQBWl5enX+g7hVNcz+RiR9eCIA1f5OU7UAIUzUY8WoBv7WUMKMD/ACxE
MPmiJUvP7ftPWzAY3KnB0IaYSX4fXtxjK17nP+LLjNkD3dH9sJRKpg0XoZdeauX0
J3ozDkIWgQrf4uzGbZsx7UjEyzMXW+clssUsgfy3jQkShA1ue/62RyCQXNaUkuxG
ZToL+NDW0NfIeBOEqLyQqQ3dAVSr/GxXn3cc7BPnQfSnPbn8o6abePmOUmh48/+F
UbO+mf0qGKFniYDWQ7CtMxMsWF/fPhgyNEcvllAmvnPvk3zSboEZnpPt1sDNz1g/
B0ZFZo9TVF46XJIWhR3HXSUL1l+A/fre87bOoIvMwcjrsYea0tC/FUrcanqoDAim
WJfgv2MzbK+yCdNTXbmtwERcWAA2/Ls14Q7ANmkd5xuE+nPhykQPQEGZGna+h3GD
57Z3YD2Iy4SIixiIMg9fnMPtqRC/YRcDIY9GalHCSyjxrX5KmSrauwz5qCmZTfTN
X7NOA3SzsNds31zuMoo5JVLmzf/0geL4lsaFkERA2nbeMpAlnz3u7h31aPlYrFWe
C4mt+fhV6RP+WKGbvDgc8btVR82eHRmcw7PlaBOnMddf2rMur4rNWtyzgCInyeij
ph4bwnG6B/aZfp7HnHl24TBUzdckwWsGrmzmOWx33epzQ2HXsygpbCLSPUVOyEdp
KIT2Q5Vv7BFP1qsH2g3xZZG0tgEgc2IqyBjYuKG+cWLYZOegZrUfCdO5vRY0+UCA
ovq8lbtimtiI6bAVAQlT3TfUxUUuM3XVEWyzVzIlrwglWE5X4tReyy9cdZpUrO4q
gCFdJEVGAQojiRx3euxNbF6ljre38+ZYp4c/TJfy9rHftoC/JWD1/kunOQEsyKj8
OCqAhpLYPkkofYP6H6+l+WqYv5jTwWZkBi5k+4HhjDimZ5rxyF45Tj0kL4zuxrRI
b873r8DhpmwmcQMhRKGKLgtFgNPs9NmFeZ30iRChGlIZQfag2wFIHm3uISbTDAbd
THEhtKW9R5VgiprCOw4qtXCoWnaKJ+zyLvdHJltLlyRctjX5wPZuFeehxjeFQb5M
JO9TPzVYBFTb6VICZRTI5+tQXYq/mtdLf1+93bH6YKOET7Ct9/GI9aYsVVF6xAex
pWLwFCGOSdjL7z7IbCaM2DG9jLkq8qz9LITaw7EuQWI/MmGBgnqcRSPkEAxafcDc
aMF4B9oY9FieHZNFcy2gv9KFwp66ow95mBhS+bgCej0YwnltESxrABw1izB0aIMX
O7KvpajcOKin72oB3HwXtUmoyO0PIU/lz0I3Bnw48hgSzVdKyOA=
-----END PUBLIC KEY-----';

    private const MESSAGE = "ML-DSA interop message: PHP 8.5 (OpenSSL 3.5) x OpenSSL 4.0 CLI\n";

    private const SIGNATURE = '
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
DxEeHyArP0JWhbHM3vUAAAAAAAAAABYnOUg=';

    /**
     * Loading the CLI keys doesn't need an engine
     */
    public function testLoadOpenSSLKeys(): void
    {
        $private = PublicKeyLoader::load(self::PRIVATE_KEY);
        $this->assertInstanceOf(PrivateKey::class, $private);
        $this->assertSame('ML-DSA-44', $private->getParameterSet());

        // genpkey wrote seed and expanded key; both are kept and written back as they came
        $components = PKCS8::load(self::PRIVATE_KEY);
        $this->assertSame(32, strlen($components['seed']));
        $this->assertSame(2560, strlen($components['expandedKey']));
        $this->assertSameNL(self::PRIVATE_KEY, $private->toString('PKCS8'));

        $public = PublicKeyLoader::load(self::PUBLIC_KEY);
        $this->assertInstanceOf(PublicKey::class, $public);
        $this->assertSame('ML-DSA-44', $public->getParameterSet());
        $this->assertSameNL(self::PUBLIC_KEY, $public->toString('PKCS8'));
    }

    public function testPublicKeyMatchesOpenSSL(): void
    {
        self::requireEngine();

        $private = MLDSA::loadPrivateKey(self::PRIVATE_KEY);
        $this->assertSameNL(self::PUBLIC_KEY, $private->getPublicKey()->toString('PKCS8'));

        // the seed alone and the expanded key alone give the same public key
        $components = PKCS8::load(self::PRIVATE_KEY);
        $seedOnly = MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44', 'seed' => $components['seed']]);
        $this->assertSameNL(self::PUBLIC_KEY, $seedOnly->getPublicKey()->toString('PKCS8'));
        $expandedOnly = MLDSA::loadFormat('Raw', ['parameterSet' => 'ML-DSA-44', 'expandedKey' => $components['expandedKey']]);
        $this->assertSameNL(self::PUBLIC_KEY, $expandedOnly->getPublicKey()->toString('PKCS8'));
    }

    public function testVerifyOpenSSLSignature(): void
    {
        self::requireEngine();

        $signature = Strings::base64_decode(preg_replace('#\s#', '', self::SIGNATURE));
        $this->assertSame(2420, strlen($signature));

        $public = MLDSA::loadPublicKey(self::PUBLIC_KEY);
        $this->assertTrue($public->verify(self::MESSAGE, $signature));
        $this->assertFalse($public->verify(rtrim(self::MESSAGE), $signature));

        // and the CLI public key verifies what phpseclib signs with the CLI private key
        $private = MLDSA::loadPrivateKey(self::PRIVATE_KEY);
        $this->assertTrue($public->verify(self::MESSAGE, $private->sign(self::MESSAGE)));
    }
}
