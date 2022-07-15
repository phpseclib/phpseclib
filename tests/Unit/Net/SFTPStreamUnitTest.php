<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Net;

use phpseclib3\Net\SFTP\Stream;
use phpseclib3\Tests\PhpseclibTestCase;

class SFTPStreamUnitTest extends PhpseclibTestCase
{
    public function testRegisterWithoutArgument(): void
    {
        $this->assertTrue(Stream::register());
        $this->assertContains('sftp', stream_get_wrappers());
        $this->assertTrue(stream_wrapper_unregister('sftp'));
    }

    public function testRegisterWithArgument(): void
    {
        $protocol = 'sftptest';
        $this->assertTrue(Stream::register($protocol));
        $this->assertContains($protocol, stream_get_wrappers());
        $this->assertTrue(stream_wrapper_unregister($protocol));
    }
}
