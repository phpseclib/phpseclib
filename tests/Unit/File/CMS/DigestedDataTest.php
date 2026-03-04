<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\File\CMS;

use phpseclib4\File\CMS;
use phpseclib4\Tests\PhpseclibTestCase;

class DigestedDataTest extends PhpseclibTestCase
{
    public function testCreate(): void
    {
        $cms = CMS::load('-----BEGIN CMS-----
MGAGCSqGSIb3DQEHBaBTMFECAQAwCwYJYIZIAWUDBAIBMB0GCSqGSIb3DQEHAaAQ
BA5oZWxsbywgd29ybGQhCgQgTcoP1fQkoxsDq4B8uud+syvy0Inu0c7hVLOv7UWN
4Nw=
-----END CMS-----');
        $this->assertTrue($cms->validate());
    }

    public function testVerify(): void
    {
        $cms = new CMS\DigestedData('hello, world!');
        $cms = CMS::load("$cms");
        $this->assertTrue($cms->validate());
    }
}
