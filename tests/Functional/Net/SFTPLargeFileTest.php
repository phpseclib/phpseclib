<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Base;
use phpseclib\Net\SFTP;

class Functional_Net_SFTPLargeFileTest extends Functional_Net_SFTPTestCase
{
    public static function setUpBeforeClass()
    {
        if (!extension_loaded('mcrypt') && !extension_loaded('openssl')) {
            self::markTestSkipped('This test depends on mcrypt or openssl for performance.');
        }
        parent::setUpBeforeClass();
    }

    /**
     * @group github298
     * @group github455
     * @group github457
     */
    public function testPutSizeLocalFile()
    {
        $tmp_filename = $this->createTempFile(128, 1024 * 1024);
        $filename = 'file-large-from-local.txt';

        $this->assertTrue(
            $this->sftp->put($filename, $tmp_filename, SFTP::SOURCE_LOCAL_FILE),
            'Failed asserting that local file could be successfully put().'
        );

        $this->assertSame(
            128 * 1024 * 1024,
            $this->sftp->size($filename),
            'Failed asserting that uploaded local file has the expected length.'
        );
    }
}
