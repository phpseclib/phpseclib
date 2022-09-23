<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Unit\File\X509;

use phpseclib3\Crypt\RSA;
use phpseclib3\File\X509;
use phpseclib3\Math\BigInteger;
use phpseclib3\Tests\PhpseclibTestCase;

class CRLTest extends PhpseclibTestCase
{
    public function testLoadCRL()
    {
        $test = file_get_contents(__DIR__ . '/crl.bin');

        $x509 = new X509();

        $x509->loadCRL($test);

        $reason = $x509->getRevokedCertificateExtension('9048354325167497831898969642461237543', 'id-ce-cRLReasons');

        $this->assertSame('unspecified', $reason);
    }

    public function testCreateCRL()
    {
        // create private key / x.509 cert for signing
        $CAPrivKey = RSA::createKey(1024);
        $CAPubKey = $CAPrivKey->getPublicKey();

        $CASubject = new X509();
        $CASubject->setDNProp('id-at-organizationName', 'phpseclib CA cert');
        $CASubject->setPublicKey($CAPubKey);

        $CAIssuer = new X509();
        $CAIssuer->setPrivateKey($CAPrivKey);
        $CAIssuer->setDN($CASubject->getDN());

        $x509 = new X509();
        $x509->makeCA();
        $result = $x509->sign($CAIssuer, $CASubject);
        $CA = $x509->saveX509($result);

        // create CRL
        $x509 = new X509();
        $crl = $x509->loadCRL($x509->saveCRL($x509->signCRL($CAIssuer, new X509())));
        $x509->revoke(new BigInteger('zzz', 256), '+1 year');
        $crl = $x509->saveCRL($x509->signCRL($CAIssuer, $x509));

        // validate newly created CRL
        $x509 = new X509();
        $x509->loadCA($CA);
        $r = $x509->loadCRL($crl);
        $this->assertArrayHasKey('parameters', $r['signatureAlgorithm']);
        $this->assertTrue($x509->validateSignature());
    }
}
