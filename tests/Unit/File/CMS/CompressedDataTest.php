<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\File\CMS;

use phpseclib4\Exception\UnsupportedValueException;
use phpseclib4\File\CMS;
use phpseclib4\Tests\PhpseclibTestCase;

class CompressedDataTest extends PhpseclibTestCase
{
    public function testDecompress(): void
    {
        if (!function_exists('zlib_decode')) {
            self::markTestSkipped('zlib_decode() not available');
        }

        // from https://github.com/phpseclib/phpseclib/issues/1211#issuecomment-344652471
        $cms = CMS::load('MIIDLgYLKoZIhvcNAQkQAQmgggMdMIIDGQIBADANBgsqhkiG9w0BCRADCDCCAwMG
CSqGSIb3DQEHAaCCAvQEggLweJydk1tvqzgUhd+R+A8orxUN4UAurfpgE4eQBFoI
kMBL5YC5NNwChpD8+kMqjeaiM6Ojsfy019pb39qWdU1HvEvqJi2LF27yLLCMUhaU
FJS3bxV54fI2o2mFazpu0rgg4StX1SUtgzJ7G+GqytIA06F3XJ2DZsY/PJi2NRm9
cvkgZfHbqEkwL8rToXIq2yLE9e1txA9nKsOpJM0FCU5XcyTIMwEKE7RYLqEiC2Ax
H7EMy/D871j/CU1JT8dVhtPiT2WZNlXZpPQ7KKAUB0k+1F+5KM1IgXPyRklDP5s8
zcknHcZ8BmVe1aRpSPhMwvRBYydpww0Xcw8vlw8ijsn/5/yPBb5y30yjb57nataM
/tJc46KJSM2jIijDtIhfuBNuyFT6l7T4V2n/NplldE2D1PQ229LXki4wgBko5VCr
vhQFYE0BJuqXd2DAOIuTcwx9U0cgRiuwBDsYny8sk5xTdXEVILyiPo5Xi8dEYmoQ
2HCvI6dX7mADY8OFwLPBeeXqln5Fprd0TVNbgspmmZM4yXauIXhHK9P36Lq+fqvb
JUw2p8LKglzOQgUe8cEq8NG6aysokD3UQ9VUFHM5rLfTXDgpoUt/TWo8SP/gHBKt
ANgPyQBqzeD9SbKHR26bZEHXp/H9YF02nbO+m7KWeG0igNIJNtq1Dx2vr+B853pp
eZTsbnu/AlmWFQhjk2QRy4hK5Vih9aTOvuotbhfuRRIuRJypXbTZHsUfZqmGSZCs
GzUFoCg3w8bmY1qEU9sZi7Gos0z/ETSXCdrSnRgpdh/PLsjzJf+rnbTd0a/WG1dQ
86eDY3/0+uJUT0DXGgpWZu+Gv0NadGIZEx5iIItYJOltddraoft1RCeK2sVc7zNj
lQn7KjqM89pWpL4kiGwiesGdqXt4HuzvCcvshWl9v4l12xqT8OCQdO5M5x9y5Ee4
3QbXD8l/t3yoqxFeF+BWyESwQAQIfOrQj+y8oCxzjkU3Q++gBLH6+1+E5x/en0Jj
cT0=');
        $this->assertStringContainsString('This is a test message', $cms->getContent());
    }

    public function testCompress(): void
    {
        if (!function_exists('zlib_encode')) {
            self::markTestSkipped('zlib_encode() not available');
        }

        $plaintext = 'ASDFASDF';
        $cms = new CMS\CompressedData($plaintext);
        $this->assertEquals($plaintext, $cms->getContent());
        $this->assertNotEmpty("$cms");
    }

    public function testGetContentRefreshesCacheAfterCompressedContentChanges(): void
    {
        if (!function_exists('zlib_encode')) {
            self::markTestSkipped('zlib_encode() not available');
        }

        $created = new CMS\CompressedData('first content');
        $loaded = CMS::load((string) $created);
        foreach ([$created, $loaded] as $cms) {
            $this->assertSame('first content', $cms->getContent());

            $cms['content']['encapContentInfo']['eContent'] = zlib_encode('updated content', ZLIB_ENCODING_DEFLATE);

            $this->assertSame('updated content', $cms->getContent());
        }
    }

    public function testGetContentRetriesInvalidPayloadAndRecovers(): void
    {
        if (!function_exists('zlib_encode') || !function_exists('zlib_decode')) {
            self::markTestSkipped('zlib_encode() or zlib_decode() not available');
        }

        $cms = new CMS\CompressedData('cached plaintext');
        $this->assertSame('cached plaintext', $cms->getContent());

        $cms['content']['encapContentInfo']['eContent'] = 'invalid compressed data';
        $warnings = 0;
        set_error_handler(static function (int $severity, string $message) use (&$warnings): bool {
            if ($severity === E_WARNING && str_contains($message, 'zlib_decode()')) {
                $warnings++;
                return true;
            }

            return false;
        });
        try {
            for ($i = 0; $i < 2; $i++) {
                try {
                    $cms->getContent();
                    self::fail('Invalid compressed content should not return cached plaintext');
                } catch (UnsupportedValueException $e) {
                    $this->assertSame('zlib_decode() returned false', $e->getMessage());
                }
            }
        } finally {
            restore_error_handler();
        }
        $this->assertSame(2, $warnings);

        $cms['content']['encapContentInfo']['eContent'] = zlib_encode('recovered plaintext', ZLIB_ENCODING_DEFLATE);
        $this->assertSame('recovered plaintext', $cms->getContent());
        $this->assertSame('recovered plaintext', $cms->getContent());
    }

    public function testGetContentCachesEmptyPlaintextAndRefreshesIt(): void
    {
        if (!function_exists('zlib_encode') || !function_exists('zlib_decode')) {
            self::markTestSkipped('zlib_encode() or zlib_decode() not available');
        }

        $cms = new CMS\CompressedData('');
        $this->assertSame('', $cms->getContent());
        $this->assertSame('', $cms->getContent());

        $cms['content']['encapContentInfo']['eContent'] = zlib_encode('nonempty plaintext', ZLIB_ENCODING_DEFLATE);
        $this->assertSame('nonempty plaintext', $cms->getContent());
        $this->assertSame('nonempty plaintext', $cms->getContent());
    }

    public function testGetContentMutationSurvivesSerialization(): void
    {
        if (!function_exists('zlib_encode') || !function_exists('zlib_decode')) {
            self::markTestSkipped('zlib_encode() or zlib_decode() not available');
        }

        $cms = CMS::load((string) new CMS\CompressedData('original plaintext'));
        $this->assertSame('original plaintext', $cms->getContent());

        $cms['content']['encapContentInfo']['eContent'] = zlib_encode('replacement plaintext', ZLIB_ENCODING_DEFLATE);
        $this->assertSame('replacement plaintext', $cms->getContent());

        $reloaded = CMS::load((string) $cms);
        $this->assertSame('replacement plaintext', $reloaded->getContent());
    }
}
