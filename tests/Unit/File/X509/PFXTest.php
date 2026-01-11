<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\File\X509;

use phpseclib4\Crypt\RSA\PrivateKey as RSAPrivateKey;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PrivateKey as ECPrivateKey;
use phpseclib4\File\PFX;
use phpseclib4\File\X509;
use phpseclib4\Tests\PhpseclibTestCase;

class PFXTest extends PhpseclibTestCase
{
    public function testEncryptedComplicated(): void
    {
        // pfx1.der contains 2x key pairs (ie. 2x X509 certs and 2x private keys)
        // and 1x "SecretBag" (an AES secret key), which phpseclib doesn't support
        // the PFX was generated with https://keystore-explorer.org/
        $temp = file_get_contents(__DIR__ . '/pfx1.der');
        $r = PFX::load($temp, 'password');

        $linearized = $r->getAll();
        $this->assertCount(4, $linearized);
        $this->assertInstanceOf(RSAPrivateKey::class, $linearized[0]);
        $this->assertInstanceOf(ECPrivateKey::class, $linearized[1]);
        $this->assertInstanceOf(X509::class, $linearized[2]);
        $this->assertInstanceOf(X509::class, $linearized[3]);

        $friendly = $r->getFriendlyNames();
        $this->assertCount(3, $friendly);
        // each of the friendly names are instances of BMPString, which encodes every character with two bytes
        // if the second byte isn't needed it's the null byte
        $this->assertSame('a', (string) $friendly[0]->toUTF8String());
        $this->assertSame('b', (string) $friendly[1]->toUTF8String());
        $this->assertSame('c', (string) $friendly[2]->toUTF8String());

        $local = $r->getLocalKeyIDs();
        $this->assertCount(3, $local);
        $this->assertSame('54696d652031373439393330383037373833', bin2hex((string) $local[0]));
        $this->assertSame('54696d652031373439393330383234303239', bin2hex((string) $local[1]));
        $this->assertSame('54696d652031373439393330383338363932', bin2hex((string) $local[2]));

        $a = $r->pluckByFriendlyName('a');
        $this->assertCount(2, $a);
        $this->assertInstanceOf(RSAPrivateKey::class, $a[0]);
        $this->assertInstanceOf(X509::class, $a[1]);
        // two objects with the same friendly name don't necessarily *have* to correspond
        // to one another but, in this case, they do
        $t1 = (string) $a[0]->getPublicKey();
        $t2 = (string) $a[1]->getPublicKey();
        $this->assertSame($t1, $t2);

        $b = $r->pluckByFriendlyName('b');
        $this->assertCount(2, $b);
        $this->assertInstanceOf(ECPrivateKey::class, $b[0]);
        $this->assertInstanceOf(X509::class, $b[1]);
        // two objects with the same friendly name don't necessarily *have* to correspond
        // to one another but, in this case, they do
        $t1 = (string) $b[0]->getPublicKey();
        $t2 = (string) $b[1]->getPublicKey();
        $this->assertSame($t1, $t2);

        // c exists as a friendly name - it just doesn't have any objects that phpseclib can deal with
        $c = $r->pluckByFriendlyName('c');
        $this->assertCount(0, $c);

        // d doesn't exist as a friendly name
        $d = $r->pluckByFriendlyName('d');
        $this->assertCount(0, $d);

        $a = $r->pluckByLocalKeyID(hex2bin('54696d652031373439393330383037373833'));
        $this->assertCount(2, $a);
        $this->assertInstanceOf(RSAPrivateKey::class, $a[0]);
        $this->assertInstanceOf(X509::class, $a[1]);
        $t1 = (string) $a[0]->getPublicKey();
        $t2 = (string) $a[1]->getPublicKey();
        $this->assertSame($t1, $t2);

        $b = $r->pluckByLocalKeyID(hex2bin('54696d652031373439393330383234303239'));
        $this->assertCount(2, $b);
        $this->assertInstanceOf(ECPrivateKey::class, $b[0]);
        $this->assertInstanceOf(X509::class, $b[1]);
        // two objects with the same friendly name don't necessarily *have* to correspond
        // to one another but, in this case, they do
        $t1 = (string) $b[0]->getPublicKey();
        $t2 = (string) $b[1]->getPublicKey();
        $this->assertSame($t1, $t2);

        $c = $r->pluckByLocalKeyID(hex2bin('54696d652031373439393330383338363932'));
        $this->assertCount(0, $c);

        // new PFX's generate in this manner do not have a friendly names or labels and are not,
        // by default, encrypted
        $new = $r->pfxFromFriendlyName('a');
        $linearized = $new->getAll();
        $this->assertCount(2, $linearized);
        $ref = '308207ff020103308207f806092a864886f70d010701a08207e9048207e5308207e1308204ed06092a864886f70d010701a08204de048204da308204d6308204d2060b2a864886f70d010c0a0101a08204c1308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100dcc02b8342cae568fd4b7855945876baf0b63d849a7fbf4803a11fb5389f7f9e68355f7e0b3da9172770d3beaaa8f9383ef1f735d8bb5876ec035d153ec2e7fe7deb5f7202e4eb56d76bba193c6f6e62eee861ffd86235cda5607b9a219b4f0299860b8caecea22a297fe571c72994ebba84ea5be8a66e94c4341cbcf6e1764bb61558adb03226c4722ec3603cc8599097720f9c1157183ee4fa0982e6973a1cc35052b724441a33dae2f4e84a3fe45c8e92f66a2cd898b577ba0c8f1aeee1b33d946c1bf38b4addfc6eff6bb628bea0afdcd2d8fee23b4bc38944e4568bd1960f707e9f754a148081b632cfcda8b04b999b487c3eeed402ce145927e8af3ca302030100010282010059f54a0624aaf05017a0b0ba1748f1a17ec4954f3b72c1ad84251df9c8c85ec65beb1c2e0e40a36e9719088113a4e662c06bf475120c4ea1afce33199c48eb27af82c29380906f432568761f209cbc5c3ec59e621778f63a06a1c9dce6c316b09585a5a13fff5ee055a7140688c5ee351dfe5a4ef80112e1370f9182840d1f1a3b979568d4ca3874422bd70bff6c72e2f40bae43c291f39bfda80692b8c47a2910047eb2c6bb7bbe3cd3fbc784add732af494a0ce442001d2fe8f400d3719dd6a4c55a344532c6938019139af56e884089d50dc492c4ea9d3517dab877867c9ddc9d908e1626928d1a8733a9a01aa430862a2e51b54676313588f73556d5b1a102818100f44898fcb45c558fb933d07ee8bc94d534f9c13e20b5c84c58565166a7142a1b6015df4b206738d00db09ad43c25c6f5ff4038de97351fd520e3aae95501b8da2b94cce015de7d0cb4379af81d300eed9f829d7c1f0815f6a4d6e510924872f0887557ee1f79f7554b078a6c7990ba7e59e2af4e387c1f1509730a7864cd987102818100e756a06b61a95904b176dbc2f284cfacbd184418be6a191bfe99f57d1dac5914824c96e048792d5430dd57812e7f60949340e6085d9a4e0be7b3a76c2b69d85638ecdf7d34d85a62e120dc167e42f2bfd72dc3a9c3a0b23cfa11ea30dbd3242bf3be609f0a0fdeb678946443f78b031ad71438b65d19712c09c25281de5bd053028180553661cf7ce6dc9dd6ffe111f4039c7347187c353cd9cc75fd36970c94e9aeca7fd9015c46805b4c100a73e7e6d752b10b0a0f0c6e78849326f6e3eea2cd87faeacaec309ad05294b4e4d4b50a117293a759bbafc96f5ba1fedc4b695d6dd2525f777765c42b1a80f13c3f2819bbc7a23d9e9a8251a7d27bd720ff1d0224c9b102818003c7cfa1519c41df28c3477e1d167c8a5720c16422207bbe905f95ba70b4b353f97924f20f5d23977fa0ee6027115fd3adc05ec1fe3d9a4ee97f6f19fe6fa1606f57b7a3452ccff553b684c23d57fcbd93d7a49dee9b7eae2e6c0286bfe0e8736b6d4e08eb522d12904fe47f93d90ab8f290db0867e7158961b37243bb0d870f02818100ee61320922a0816b189099a6d3d33ac0ff3b8ec406c2c325c1e8cfa4f67f6d8f59feb993c6fb583b65c6b11b8381c23fc549231063fa25881907327e30f7dbfd45c11271443e44f909e5a9da8a68a06299fc0fe83609c027dc34c50765b332e1c2496e0eca6ea0677c8aef3a7131c73136445975188a4d6add873c15c80c377f308202ec06092a864886f70d010701a08202dd048202d9308202d5308202d1060b2a864886f70d010c0a0103a08202c0308202bc060a2a864886f70d01091601a08202ac048202a8308202a43082018ca00302010202145b4aba0c0ec1c13ab8a401a5b0b201977000c5aa300d06092a864886f70d01010b0500300c310a300806035504030c0161301e170d3235303631343139353330385a170d3236303631343139353330385a300c310a300806035504030c016130820122300d06092a864886f70d01010105000382010f003082010a0282010100dcc02b8342cae568fd4b7855945876baf0b63d849a7fbf4803a11fb5389f7f9e68355f7e0b3da9172770d3beaaa8f9383ef1f735d8bb5876ec035d153ec2e7fe7deb5f7202e4eb56d76bba193c6f6e62eee861ffd86235cda5607b9a219b4f0299860b8caecea22a297fe571c72994ebba84ea5be8a66e94c4341cbcf6e1764bb61558adb03226c4722ec3603cc8599097720f9c1157183ee4fa0982e6973a1cc35052b724441a33dae2f4e84a3fe45c8e92f66a2cd898b577ba0c8f1aeee1b33d946c1bf38b4addfc6eff6bb628bea0afdcd2d8fee23b4bc38944e4568bd1960f707e9f754a148081b632cfcda8b04b999b487c3eeed402ce145927e8af3ca30203010001300d06092a864886f70d01010b050003820101005e8b9e032b970ae98e0a798f6a071a0e7da33c9702840d89b8bfd17e3bccfa1967351a5cad8c95e0b8f0e0b52a0c9e6b2481fb820c8de5dfdf245c77de100aa1a6851ae26a13a24f6ad1ee4ceb126e54ba597995b952da6efb218fa833a33a9dbb754874e7adf2f8bbbdfc89a6a1e96dd63d1d3c862cdf833447de7ef2a5c67face4447946cc59c6b04760b779e11ff497a5a4636560e588daf13b8c293d784cb73aff1a17c4e8b2877edc90ea7983ba4a28321b9aac4b1b6eca0218b7cb23598f6b05b48eb0330f12f460e8ff14d9f8486ec79227b900c6aa272ee0748b9a3875d0e2c0fa106fa351c12d4ca2c435288cacb3b91ff3bf62b6c1f4b0d4a9c202';
        // hex2bin($ref) successfully decodes with the following:
        // openssl pkcs12 -info -in test.der -nodes
        $this->assertSame($ref, bin2hex("$new"));

        $old = "$r";
        $this->assertIsString($old);
        $r->removePassword();
        $new = "$r";
        $this->assertIsString($new);
        $this->assertNotEquals($old, $new);
    }

    public function testUnencryptedSimple(): void
    {
        $temp = file_get_contents(__DIR__ . '/pfx2.der');
        $pfx = PFX::load($temp);
        $old = "$pfx";
        $this->assertIsString($old);
        $pfx->setPassword('password');
        $new = "$pfx";
        $this->assertIsString($new);
        $this->assertNotEquals($old, $new);

        $x509 = new X509(EC::createKey('nistp256')->getPublicKey());
        $old = "$x509";
        $pfx->sign($x509);
        $new = "$x509";
        $this->assertIsString($new);
        $this->assertNotEquals($old, $new);
    }

    public function testEncryptedNoMAC(): void
    {
        $temp = file_get_contents(__DIR__ . '/pfx3.der');
        $pfx = PFX::load($temp, 'password');
        $old = "$pfx";
        $this->assertIsString($old);
    }

    public function testUnencryptedWithMAC(): void
    {
        $temp = file_get_contents(__DIR__ . '/pfx4.der');
        $pfx = PFX::load($temp);
        $old = "$pfx";
        $this->assertIsString($old);
    }

    public function testMSExport(): void
    {
        $temp = file_get_contents(__DIR__ . '/pfx5.der');
        $pfx = PFX::load($temp, 'password');
        $old = "$pfx";
        $this->assertIsString($old);
    }

    public function testCreatePFX(): void
    {
        $key = EC::createKey('Ed25519');
        $x509 = new X509($key->getPublicKey());
        $x509->setDN('O=phpseclib');
        $x509->makeCA();
        $key->sign($x509);
        $pfx = new PFX();
        $pfx->add($key);
        $pfx->add($x509);

        $key = EC::createKey('nistp256');
        $x509 = new X509($key->getPublicKey());
        $pfx->sign($x509);

        $this->assertIsString("$pfx");

        X509::addCA((string) $pfx->getCertificates()[0]);
        $this->assertTrue($x509->validateSignature());
    }
}
