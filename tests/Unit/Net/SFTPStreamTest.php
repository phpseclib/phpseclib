<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Net\SFTP\Stream;

class Unit_Net_SFTPStreamTest extends PhpseclibTestCase
{
    public function testRegisterWithoutArgument()
    {
        $this->assertTrue(Stream::register());
        $this->assertContains('sftp', stream_get_wrappers());
        $this->assertTrue(stream_wrapper_unregister('sftp'));
    }

    public function testRegisterWithArgument()
    {
        $protocol = 'sftptest';
        $this->assertTrue(Stream::register($protocol));
        $this->assertContains($protocol, stream_get_wrappers());
        $this->assertTrue(stream_wrapper_unregister($protocol));
    }
}
