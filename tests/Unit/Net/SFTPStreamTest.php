<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Unit_Net_SFTPStreamTest extends PhpseclibTestCase
{
    public function testRegisterWithoutArgument()
    {
        $this->assertTrue(Net_SFTP_Stream::register());
        $this->assertContains('sftp', stream_get_wrappers());
        $this->assertTrue(stream_wrapper_unregister('sftp'));
    }

    public function testRegisterWithArgument()
    {
        $protocol = 'sftptest';
        $this->assertTrue(Net_SFTP_Stream::register($protocol));
        $this->assertContains($protocol, stream_get_wrappers());
        $this->assertTrue(stream_wrapper_unregister($protocol));
    }
}
