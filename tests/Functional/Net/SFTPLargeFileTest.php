<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib3\Tests\Functional\Net;

use phpseclib3\Net\SFTP;

class SFTPLargeFileTest extends SFTPTestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('This test depends on openssl for performance.');
        }
        self::ensureConstant('CRYPT_HASH_MODE', 3);
        parent::setUpBeforeClass();
    }

    /**
     * @group github298
     * @group github455
     * @group github457
     */
    public function testPutSizeLocalFile(): void
    {
        $tmp_filename = $this->createTempFile(128, 1024 * 1024);
        $filename = 'file-large-from-local.txt';

        $this->assertTrue(
            $this->sftp->put($filename, $tmp_filename, SFTP::SOURCE_LOCAL_FILE),
            'Failed asserting that local file could be successfully put().'
        );

        $this->assertSame(
            128 * 1024 * 1024,
            $this->sftp->filesize($filename),
            'Failed asserting that uploaded local file has the expected length.'
        );
    }
}
