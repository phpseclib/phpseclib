<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Unit\Crypt\EC;

use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\Curves\Ed448;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\File\ASN1;
use phpseclib3\Tests\PhpseclibTestCase;

class CurveTest extends PhpseclibTestCase
{
    public function curves()
    {
        $curves = [];
        foreach (new \DirectoryIterator(__DIR__ . '/../../../../phpseclib/Crypt/EC/Curves/') as $file) {
            if ($file->getExtension() != 'php') {
                continue;
            }
            $testName = $file->getBasename('.php');
            if ($testName == 'Curve25519' || $testName == 'Curve448') {
                continue;
            }
            $class = 'phpseclib3\Crypt\EC\Curves\\' . $testName;
            $reflect = new \ReflectionClass($class);
            if ($reflect->isFinal()) {
                continue;
            }
            $curves[] = [$testName];
        }

        return $curves;
    }

    public function allCurves()
    {
        $curves = [];
        foreach (new \DirectoryIterator(__DIR__ . '/../../../../phpseclib/Crypt/EC/Curves/') as $file) {
            if ($file->getExtension() != 'php') {
                continue;
            }
            $testName = $file->getBasename('.php');
            if ($testName == 'Curve25519' || $testName == 'Curve448') {
                continue;
            }
            $curves[] = [$testName];
        }

        return $curves;
    }

    public function curvesWithOIDs()
    {
        $class = new \ReflectionClass('phpseclib3\Crypt\EC\Formats\Keys\PKCS8');

        $initialize = $class->getMethod('initialize_static_variables');
        $initialize->setAccessible(true);
        $initialize->invoke(null);

        $property = $class->getProperty('curveOIDs');
        $property->setAccessible(true);

        $curves = [];

        foreach ($property->getValue() as $curve => $oid) {
            $curves[] = [$curve];
        }

        return $curves;
    }

    /**
     * Verify that the base points are correct and verify the finite field math
     *
     * @dataProvider curves
     */
    public function testBasePoint($name)
    {
        $class = 'phpseclib3\Crypt\EC\Curves\\' . $name;
        $curve = new $class();
        $this->assertTrue($curve->verifyPoint($curve->getBasePoint()), "Failed to verify basepoint of curve $name");
    }

    /**
     * Verify the correctness of the point addition / doubling / multiplication algorithms
     *
     * @dataProvider curves
     * @requires PHP 7.0
     */
    public function testKeyGeneration($name)
    {
        $class = 'phpseclib3\Crypt\EC\Curves\\' . $name;
        $curve = new $class();
        $dA = $curve->createRandomMultiplier();
        $QA = $curve->multiplyPoint($curve->getBasePoint(), $dA);
        $this->assertTrue($curve->verifyPoint($QA), "Failed to verify point multiplication on curve $name with $dA");
    }

    /**
     * Verify that OIDs have corresponding curve class
     *
     * @dataProvider curvesWithOIDs
     */
    public function testCurveExistance($name)
    {
        $this->assertFileExists(__DIR__ . "/../../../../phpseclib/Crypt/EC/Curves/$name.php");
    }

    /**
     * Verify that all named curves have a corresponding OID
     *
     * @dataProvider allCurves
     */
    public function testOIDExistance($name)
    {
        switch ($name) {
            case 'Ed25519':
            case 'Ed448':
                self::markTestSkipped('Ed25519 / Ed448 OIDs are treated a little differently');
        }
        $this->assertNotSame(ASN1::getOID($name), $name);
    }

    /**
     * Sign with internal engine, verify with best engine
     *
     * @dataProvider curves
     * @requires PHP 7.0
     */
    public function testInternalSign($name)
    {
        // tests utilizing dataProvider only seem to output when all the dataProvider input
        // has been exhausted. ie. when this test has been ran on every curve. on my local
        // system it takes about 2.5m for this test to run, with the most time consuming curves
        // being sect571r1 and sect571k1, which take about 30s each. on Travis CI, however,
        // these curves seem to take about 2m each to run:
        // https://travis-ci.org/terrafrost/phpseclib/jobs/450262081
        // because of the 10m timeout that Travis CI has this means that there's a very
        // good chance the binary curves (sect*) will timeout before the test is able to
        // output anything
        if (substr($name, 0, 4) == 'sect') {
            self::markTestSkipped('Binary field curves are being skipped');
        }

        $plaintext = 'zzz';

        EC::useInternalEngine();
        $privatekey = EC::createKey($name);
        $publickey = $privatekey->getPublicKey();
        $sig = $privatekey->sign($plaintext);

        EC::useBestEngine();
        $this->assertTrue($publickey->verify($plaintext, $sig));
    }

    public function testCanSignWithAnEncryptedPrivateKey()
    {
        EC::useBestEngine();

        $plaintext = 'zzz';

        $privatekey = EC::createKey('Ed25519')->withPassword('foo');
        $publickey = $privatekey->getPublicKey();
        $sig = $privatekey->sign($plaintext);

        $this->assertTrue($publickey->verify($plaintext, $sig));
    }

    /**
     * Sign with best engine, verify with internal engine
     *
     * @dataProvider curves
     * @requires PHP 7.0
     */
    public function testInternalVerify($name)
    {
        if (substr($name, 0, 4) == 'sect') {
            self::markTestSkipped('Binary field curves are being skipped');
        }

        $plaintext = 'zzz';

        EC::useBestEngine();
        $privatekey = EC::createKey($name);
        $publickey = $privatekey->getPublicKey();
        $sig = $privatekey->sign($plaintext);

        EC::useInternalEngine();
        $this->assertTrue($publickey->verify($plaintext, $sig));
    }

    /**
     * Ed448 test vectors from https://tools.ietf.org/html/rfc8032#section-7.4
     */
    public function testEd448TestVectors()
    {
        EC::addFileFormat(Ed448PublicKey::class);
        EC::addFileFormat(Ed448PrivateKey::class);

        $private = pack('H*', '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b');
        $public = pack('H*', '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180');

        $privateKey = PublicKeyLoader::load($private);
        $publicKey = PublicKeyLoader::load($public);

        $expected = '533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980' .
                    'ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign('')));
        $this->assertTrue($publicKey->verify('', $sig));

        $private = pack('H*', 'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e');
        $public = pack('H*', '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480');

        $privateKey = PublicKeyLoader::load($private);
        $publicKey = PublicKeyLoader::load($public);

        $expected = '26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd77980' .
                    '5e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign("\x03")));
        $this->assertTrue($publicKey->verify("\x03", $sig));

        $publicKey = $publicKey->withContext(pack('H*', '666f6f'));
        $privateKey = $privateKey->withContext(pack('H*', '666f6f'));

        $expected = 'd4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea00' .
                    '0c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign("\x03")));
        $this->assertTrue($publicKey->verify("\x03", $sig));

        $private = pack('H*', '258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b');
        $public = pack('H*', '3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580');

        $privateKey = PublicKeyLoader::load($private);
        $publicKey = PublicKeyLoader::load($public);

        $message = pack('H*', '64a65f3cdedcdd66811e2915');

        $expected = '7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00' .
                    'b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign($message)));
        $this->assertTrue($publicKey->verify($message, $sig));

        $private = pack('H*', '7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e');
        $public = pack('H*', 'b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80');

        $privateKey = PublicKeyLoader::load($private);
        $publicKey = PublicKeyLoader::load($public);

        $message = pack('H*', '64a65f3cdedcdd66811e2915e7');

        $expected = '6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c027468675ecf645a83176c0d7323a2ccde2d80' .
                    'efe5a1268e8aca1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf56b4e7e0ba5519234d047155ac727a1053100';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign($message)));
        $this->assertTrue($publicKey->verify($message, $sig));

        $private = pack('H*', 'd65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01');
        $public = pack('H*', 'df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00');

        $privateKey = PublicKeyLoader::load($private);
        $publicKey = PublicKeyLoader::load($public);

        $message = 'bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944';
        $message = pack('H*', $message);

        $expected = '554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b18dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a080' .
                    '1b63d45b3b722ef552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba5f30e88e36ec2703b349ca229c2670833900';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign($message)));
        $this->assertTrue($publicKey->verify($message, $sig));

        $private = pack('H*', '2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5');
        $public = pack('H*', '79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00');

        $privateKey = PublicKeyLoader::load($private);
        $publicKey = PublicKeyLoader::load($public);

        $message = '15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567cfa80e12928bb542330e8409f3174504107ecd5efac61ae7504dabe2a602ede89e5cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072fc1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a60' .
                   '39c3c2a39f0e4d832be432dfa9a706a6e5c7e19f397964ca4258002f7c0541b590316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce012d901015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409a9981b51878fd6fc110624dcbcde0bf7a69ccce38fabdf86f3bef6044819de11';
        $message = pack('H*', $message);

        $expected = 'c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880' .
                    'e8d4f1cfce2d7a61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc60987fd08527c1a8e80d5823e65cafe2a3d00';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign($message)));
        $this->assertTrue($publicKey->verify($message, $sig));

        $private = pack('H*', '872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8');
        $public = pack('H*', 'a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400');

        $privateKey = PublicKeyLoader::load($private);
        $publicKey = PublicKeyLoader::load($public);

        $message = '6ddf802e1aae4986935f7f981ba3f0351d6273c0a0c22c9c0e8339168e675412a3debfaf435ed651558007db4384b650fcc07e3b586a27a4f7a00ac8a6fec2cd86ae4bf1570c41e6a40c931db27b2faa15a8cedd52cff7362c4e6e23daec0fbc3a79b6806e316efcc7b68119bf46bc76a26067a53f296dafdbdc11c77f7777e9' .
                   '72660cf4b6a9b369a6665f02e0cc9b6edfad136b4fabe723d2813db3136cfde9b6d044322fee2947952e031b73ab5c603349b307bdc27bc6cb8b8bbd7bd323219b8033a581b59eadebb09b3c4f3d2277d4f0343624acc817804728b25ab797172b4c5c21a22f9c7839d64300232eb66e53f31c723fa37fe387c7d3e50bdf9813' .
                   'a30e5bb12cf4cd930c40cfb4e1fc622592a49588794494d56d24ea4b40c89fc0596cc9ebb961c8cb10adde976a5d602b1c3f85b9b9a001ed3c6a4d3b1437f52096cd1956d042a597d561a596ecd3d1735a8d570ea0ec27225a2c4aaff26306d1526c1af3ca6d9cf5a2c98f47e1c46db9a33234cfd4d81f2c98538a09ebe76998' .
                   'd0d8fd25997c7d255c6d66ece6fa56f11144950f027795e653008f4bd7ca2dee85d8e90f3dc315130ce2a00375a318c7c3d97be2c8ce5b6db41a6254ff264fa6155baee3b0773c0f497c573f19bb4f4240281f0b1f4f7be857a4e59d416c06b4c50fa09e1810ddc6b1467baeac5a3668d11b6ecaa901440016f389f80acc4db9' .
                   '77025e7f5924388c7e340a732e554440e76570f8dd71b7d640b3450d1fd5f0410a18f9a3494f707c717b79b4bf75c98400b096b21653b5d217cf3565c9597456f70703497a078763829bc01bb1cbc8fa04eadc9a6e3f6699587a9e75c94e5bab0036e0b2e711392cff0047d0d6b05bd2a588bc109718954259f1d86678a579a3' .
                   '120f19cfb2963f177aeb70f2d4844826262e51b80271272068ef5b3856fa8535aa2a88b2d41f2a0e2fda7624c2850272ac4a2f561f8f2f7a318bfd5caf9696149e4ac824ad3460538fdc25421beec2cc6818162d06bbed0c40a387192349db67a118bada6cd5ab0140ee273204f628aad1c135f770279a651e24d8c14d75a605' .
                   '9d76b96a6fd857def5e0b354b27ab937a5815d16b5fae407ff18222c6d1ed263be68c95f32d908bd895cd76207ae726487567f9a67dad79abec316f683b17f2d02bf07e0ac8b5bc6162cf94697b3c27cd1fea49b27f23ba2901871962506520c392da8b6ad0d99f7013fbc06c2c17a569500c8a7696481c1cd33e9b14e40b82e' .
                   '79a5f5db82571ba97bae3ad3e0479515bb0e2b0f3bfcd1fd33034efc6245eddd7ee2086ddae2600d8ca73e214e8c2b0bdb2b047c6a464a562ed77b73d2d841c4b34973551257713b753632efba348169abc90a68f42611a40126d7cb21b58695568186f7e569d2ff0f9e745d0487dd2eb997cafc5abf9dd102e62ff66cba87';
        $message = pack('H*', $message);

        $expected = 'e301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bddf7f4c8f1cb49f6396afc8a70abe6d8aef0db478d4c6b29700' .
                    '76c6a0484fe76d76b3a97625d79f1ce240e7c576750d295528286f719b413de9ada3e8eb78ed573603ce30d8bb761785dc30dbc320869e1a00';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign($message)));
        $this->assertTrue($publicKey->verify($message, $sig));
    }

    /**
     * Ed25519 test vectors from https://tools.ietf.org/html/rfc8032#section-7.1 (and 7.2)
     */
    public function testEd25519TestVectors()
    {
        EC::useBestEngine();

        $private = pack('H*', '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
        $public = pack('H*', 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');

        $privateKey = EC::loadFormat('libsodium', $private . $public); // libsodium format
        $publicKey = EC::loadFormat('libsodium', $public);

        $expected = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' .
                    '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign('')));
        $this->assertTrue($publicKey->verify('', $sig));

        $private = pack('H*', '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');
        $public = pack('H*', '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c');

        $privateKey = EC::loadFormat('libsodium', $private . $public);
        $publicKey = EC::loadFormat('libsodium', $public);

        $expected = '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da' .
                    '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign("\x72")));
        $this->assertTrue($publicKey->verify("\x72", $sig));

        $private = pack('H*', 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7');
        $public = pack('H*', 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025');

        $privateKey = EC::loadFormat('libsodium', $private . $public); // libsodium format
        $publicKey = EC::loadFormat('libsodium', $public);

        $expected = '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac' .
                    '18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign("\xaf\x82")));
        $this->assertTrue($publicKey->verify("\xaf\x82", $sig));

        $private = pack('H*', 'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5');
        $public = pack('H*', '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e');

        $privateKey = EC::loadFormat('libsodium', $private . $public); // libsodium format
        $publicKey = EC::loadFormat('libsodium', $public);

        $message = '08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98' .
                   'fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8' .
                   '79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d' .
                   '658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc' .
                   '1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe' .
                   'ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e' .
                   '06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef' .
                   'efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7' .
                   'aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1' .
                   '85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2' .
                   'd17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24' .
                   '554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270' .
                   '88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc' .
                   '2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07' .
                   '07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba' .
                   'b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a' .
                   'ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e' .
                   'c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7' .
                   '51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c' .
                   '42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8' .
                   'ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df' .
                   'f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08' .
                   'd78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649' .
                   'de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4' .
                   '88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3' .
                   '2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e' .
                   '6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f' .
                   'b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5' .
                   '0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1' .
                   '369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d' .
                   'b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c' .
                   '0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0';
        $message = pack('H*', $message);

        $expected = '0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350' .
                    'aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign($message)));
        $this->assertTrue($publicKey->verify($message, $sig));

        $private = pack('H*', '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42');
        $public = pack('H*', 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf');

        $privateKey = EC::loadFormat('libsodium', $private . $public);
        $publicKey = EC::loadFormat('libsodium', $public);

        $message = 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' .
                   '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';
        $message = pack('H*', $message); // hash('sha512', 'abc')

        $expected = 'dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589' .
                    '09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign($message)));
        $this->assertTrue($publicKey->verify($message, $sig));

        $private = pack('H*', '0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6');
        $public = pack('H*', 'dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292');

        $privateKey = EC::loadFormat('libsodium', $private . $public);
        $publicKey = EC::loadFormat('libsodium', $public);

        $privateKey = $privateKey->withContext("\x62\x61\x72");
        $publicKey = $publicKey->withContext("\x62\x61\x72");

        $message = 'f726936d19c800494e3fdaff20b276a8';
        $message = pack('H*', $message);

        $expected = 'fc60d5872fc46b3aa69f8b5b4351d5808f92bcc044606db097abab6dbcb1aee3' .
                    '216c48e8b3b66431b5b186d1d28f8ee15a5ca2df6668346291c2043d4eb3e90d';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign($message)));
        $this->assertTrue($publicKey->verify($message, $sig));

        $private = pack('H*', '0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6');
        $public = pack('H*', 'dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292');

        $privateKey = EC::loadFormat('libsodium', $private . $public);
        $publicKey = EC::loadFormat('libsodium', $public);

        $privateKey = $privateKey->withContext("\x66\x6f\x6f");
        $publicKey = $publicKey->withContext("\x66\x6f\x6f");

        $message = '508e9e6882b979fea900f62adceaca35';
        $message = pack('H*', $message);

        $expected = '8b70c1cc8310e1de20ac53ce28ae6e7207f33c3295e03bb5c0732a1d20dc6490' .
                    '8922a8b052cf99b7c4fe107a5abb5b2c4085ae75890d02df26269d8945f84b0b';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign($message)));
        $this->assertTrue($publicKey->verify($message, $sig));

        $private = pack('H*', 'ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560');
        $public = pack('H*', '0f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772');

        $privateKey = EC::loadFormat('libsodium', $private . $public);
        $publicKey = EC::loadFormat('libsodium', $public);

        $privateKey = $privateKey->withContext("\x66\x6f\x6f");
        $publicKey = $publicKey->withContext("\x66\x6f\x6f");

        $message = 'f726936d19c800494e3fdaff20b276a8';
        $message = pack('H*', $message);

        $expected = '21655b5f1aa965996b3f97b3c849eafba922a0a62992f73b3d1b73106a84ad85' .
                    'e9b86a7b6005ea868337ff2d20a7f5fbd4cd10b0be49a68da2b2e0dc0ad8960f';
        $this->assertSame($expected, bin2hex($sig = $privateKey->sign($message)));
        $this->assertTrue($publicKey->verify($message, $sig));
    }

    public function testRandomSignature()
    {
        $message = 'hello, world!';
        $private = PublicKeyLoader::load('PuTTY-User-Key-File-2: ecdsa-sha2-nistp256
Encryption: none
Comment: ecdsa-key-20181105
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJEXCsWA8s18
m25MJlVE1urbXPYFi4q8oMbb2H0kE2f5WPxizsKXRmb1J68paXQizryL9fC4FTqI
CJ1+UnaPfk0=
Private-Lines: 1
AAAAIQDwaPlajbXY1SxhuwsUqN1CEZ5g4adsbmJsKm+ZbUVm4g==
Private-MAC: b85ca0eb7c612df5d18af85128821bd53faaa3ef');
        $public = $private->getPublicKey();

        $signature1 = $private->sign($message, 'ASN1');
        $signature2 = $private->sign($message, 'ASN1');
        // phpseclib's EC implementation uses a CSPRNG to generate the k parameter.
        // used correctly this should result in different signatures every time.
        // RFC6979 describes a deterministic EC scheme wherein two signatures for the same
        // plaintext would yield the same value so if that were to be switched to then this
        // unit test would need to be updated
        $this->assertNotEquals($signature1, $signature2);

        $this->assertTrue($public->verify($message, $signature1, 'ASN1'));
        $this->assertTrue($public->verify($message, $signature2, 'ASN1'));

        $signature1 = $private->sign($message, 'SSH2');
        $signature2 = $private->sign($message, 'SSH2');
        $this->assertNotEquals($signature1, $signature2);
        $this->assertTrue($public->verify($message, $signature1, 'SSH2'));
        $this->assertTrue($public->verify($message, $signature2, 'SSH2'));

        $signature = $private->sign($message, 'Raw');
        $this->assertTrue($public->verify($message, $signature, 'Raw'));
    }

    public function testBadRSEd25519()
    {
        // see https://research.nccgroup.com/2021/11/08/technical-advisory-arbitrary-signature-forgery-in-stark-bank-ecdsa-libraries/
        $public = PublicKeyLoader::load('-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE1zY+JIBlt8l+1I2f0ItA6oauDx9bFsm6
hk6TVQ4mP3lH+96p9keQBMRAY1D5znOyPk9107PceO+3kwoat1zKzw==
-----END PUBLIC KEY-----');

        $signature = base64_decode('MAYCAQACAQA=');
        $message = 'hello, world!';

        $this->assertFalse($public->verify($message, $signature));
    }
}
