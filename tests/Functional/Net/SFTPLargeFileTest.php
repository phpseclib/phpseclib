<?php
echo "LOADING LARGE FILE TEST\r\n";

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'Crypt/Base.php';

class Functional_Net_SFTPLargeFileTest extends PhpseclibFunctionalTestCase
{
    protected $sftp;
    protected $scratchDir;

    static public function setUpBeforeClass()
    {
echo "SETTING UP BEFORE CLASS\r\n";
        if (!extension_loaded('mcrypt') && !extension_loaded('openssl')) {
            self::markTestSkipped('This test depends on mcrypt or openssl for performance.');
        }
        parent::setUpBeforeClass();
    }

    public function setUp()
    {
echo "SETUP\r\n";
        $this->scratchDir = uniqid('phpseclib-sftp-large-scratch-');

        $this->sftp = new Net_SFTP($this->getEnv('SSH_HOSTNAME'));
        $this->assertTrue($this->sftp->login(
            $this->getEnv('SSH_USERNAME'),
            $this->getEnv('SSH_PASSWORD')
        ));
        $this->assertTrue($this->sftp->mkdir($this->scratchDir));
        $this->assertTrue($this->sftp->chdir($this->scratchDir));
    }

    public function tearDown()
    {
echo "TEAR DOWN\r\n";
        if ($this->sftp) {
            $this->sftp->chdir($this->getEnv('SSH_HOME'));
            $this->sftp->delete($this->scratchDir);
        }
        parent::tearDown();
    }

    /**
    * @group github298
    * @group github455
    * @group github457
    */
    public function testPutSizeLocalFile()
    {
echo "test put size local file\r\n";
        $tmp_filename = $this->createTempFile(128, 1024 * 1024);
        $filename = 'file-large-from-local.txt';

        $this->assertTrue(
            $this->sftp->put($filename, $tmp_filename, NET_SFTP_LOCAL_FILE),
            'Failed asserting that local file could be successfully put().'
        );

        $this->assertSame(
            128 * 1024 * 1024,
            $this->sftp->size($filename),
            'Failed asserting that uploaded local file has the expected length.'
        );
    }
}
