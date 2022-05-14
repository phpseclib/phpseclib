<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

// declare(strict_types=1);

namespace phpseclib3\Tests\Unit\File\X509;

use phpseclib3\File\X509;
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
}
