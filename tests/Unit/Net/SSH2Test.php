<?php

/**
 * @author    Marc Scholten <marc@pedigital.de>
 * @copyright 2013 Marc Scholten
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Unit_Net_SSH2Test extends PhpseclibTestCase
{
    public function formatLogDataProvider()
    {
        return array(
            array(
                array('hello world'),
                array('<--'),
                "<--\r\n00000000  68:65:6c:6c:6f:20:77:6f:72:6c:64                 hello world\r\n\r\n"
            ),
            array(
                array('hello', 'world'),
                array('<--', '<--'),
                "<--\r\n00000000  68:65:6c:6c:6f                                   hello\r\n\r\n" .
                "<--\r\n00000000  77:6f:72:6c:64                                   world\r\n\r\n"
            ),
        );
    }

    /**
     * @dataProvider formatLogDataProvider
     */
    public function testFormatLog(array $message_log, array $message_number_log, $expected)
    {
        $ssh = $this->createSSHMock();

        $result = $ssh->_format_log($message_log, $message_number_log);
        $this->assertEquals($expected, $result);
    }

    public function testGenerateIdentifier()
    {
        $identifier = $this->createSSHMock()->_generate_identifier();
        $this->assertStringStartsWith('SSH-2.0-phpseclib_2.0', $identifier);

        if (extension_loaded('libsodium')) {
            $this->assertContains('libsodium', $identifier);
        }

        if (extension_loaded('openssl')) {
            $this->assertContains('openssl', $identifier);
            $this->assertNotContains('mcrypt', $identifier);
        } elseif (extension_loaded('mcrypt')) {
            $this->assertNotContains('openssl', $identifier);
            $this->assertContains('mcrypt', $identifier);
        } else {
            $this->assertNotContains('openssl', $identifier);
            $this->assertNotContains('mcrypt', $identifier);
        }

        if (extension_loaded('gmp')) {
            $this->assertContains('gmp', $identifier);
            $this->assertNotContains('bcmath', $identifier);
        } elseif (extension_loaded('bcmath')) {
            $this->assertNotContains('gmp', $identifier);
            $this->assertContains('bcmath', $identifier);
        } else {
            $this->assertNotContains('gmp', $identifier);
            $this->assertNotContains('bcmath', $identifier);
        }
    }

    public function testGetExitStatusIfNotConnected()
    {
        $ssh = $this->createSSHMock();

        $this->assertFalse($ssh->getExitStatus());
    }

    public function testPTYIDefaultValue()
    {
        $ssh = $this->createSSHMock();
        $this->assertFalse($ssh->isPTYEnabled());
    }

    public function testEnablePTY()
    {
        $ssh = $this->createSSHMock();

        $ssh->enablePTY();
        $this->assertTrue($ssh->isPTYEnabled());

        $ssh->disablePTY();
        $this->assertFalse($ssh->isPTYEnabled());
    }

    public function testQuietModeDefaultValue()
    {
        $ssh = $this->createSSHMock();

        $this->assertFalse($ssh->isQuietModeEnabled());
    }

    public function testEnableQuietMode()
    {
        $ssh = $this->createSSHMock();

        $ssh->enableQuietMode();
        $this->assertTrue($ssh->isQuietModeEnabled());

        $ssh->disableQuietMode();
        $this->assertFalse($ssh->isQuietModeEnabled());
    }

    public function testDefaultKexAlgorithms()
    {
        $ssh = $this->createSSHMock();

        $this->assertSame(
            array (
                'curve25519-sha256@libssh.org',
                'diffie-hellman-group1-sha1',
                'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1',
                'diffie-hellman-group-exchange-sha256',
            ),
            $ssh->kex_algorithms
        );
    }

    public function testOverwrittenKexAlgorithms()
    {
        $ssh = $this->createSSHMock();
        $ssh->setKexAlgorithms(array(
            'curve25519-sha256@libssh.org',
            'diffie-hellman-group1-sha1',
            'diffie-hellman-group14-sha1',
        ));

        $this->assertSame(
            array (
                'curve25519-sha256@libssh.org',
                'diffie-hellman-group1-sha1',
                'diffie-hellman-group14-sha1',
            ),
            $ssh->kex_algorithms
        );
    }

    public function testUnsupportedKexAlgorithms()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Notice', 'Kex algorithms not supported: unsupported-algorithm');
        $ssh = $this->createSSHMock();
        $ssh->setKexAlgorithms(array(
            'curve25519-sha256@libssh.org',
            'unsupported-algorithm'
        ));
    }

    public function testDefaultServerHostKeyAlgorithms()
    {
        $ssh = $this->createSSHMock();

        $this->assertSame(
            array (
                'ssh-rsa',
                'ssh-dss'
            ),
            $ssh->server_host_key_algorithms
        );
    }

    public function testOverwrittenServerHostKeyAlgorithms()
    {
        $ssh = $this->createSSHMock();
        $ssh->setServerHostKeyAlgorithms(array(
            'ssh-rsa'
        ));

        $this->assertSame(
            array (
                'ssh-rsa'
            ),
            $ssh->server_host_key_algorithms
        );
    }

    public function testUnsupportedServerHostKeyAlgorithms()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Notice', 'Server host key algorithms not supported: unsupported-algorithm');
        $ssh = $this->createSSHMock();
        $ssh->setServerHostKeyAlgorithms(array(
            'ssh-rsa',
            'unsupported-algorithm'
        ));
    }

    public function testDefaultMACAlgorithms()
    {
        $ssh = $this->createSSHMock();

        $this->assertSame(
            array (
                'hmac-sha2-256',
                'hmac-sha1-96',
                'hmac-sha1',
                'hmac-md5-96',
                'hmac-md5',
            ),
            $ssh->getMACAlgorithms()
        );
    }

    public function testOverwrittenMACAlgorithms()
    {
        $ssh = $this->createSSHMock();
        $ssh->setMACAlgorithms(array(
            'hmac-sha2-256',
            'hmac-sha1-96',
            'hmac-sha1'
        ));

        $this->assertSame(
            array (
                'hmac-sha2-256',
                'hmac-sha1-96',
                'hmac-sha1'
            ),
            $ssh->mac_algorithms
        );
    }

    public function testUnsupportedMACAlgorithms()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Notice', 'MAC algorithms not supported: unsupported-algorithm');
        $ssh = $this->createSSHMock();
        $ssh->setMACAlgorithms(array(
            'hmac-sha2-256',
            'unsupported-algorithm'
        ));
    }

    public function testDefaultCompressionAlgorithms()
    {
        $ssh = $this->createSSHMock();

        $this->assertSame(
            array (
                'none'
            ),
            $ssh->getCompressionAlgorithms()
        );
    }

    public function testOverwrittenCompressionAlgorithms()
    {
        $ssh = $this->createSSHMock();
        $ssh->setCompressionAlgorithms(array(
            'zlib'
        ));

        $this->assertSame(
            array (
                'zlib'
            ),
            $ssh->getCompressionAlgorithms()
        );
    }

    public function testUnsupportedCompressionAlgorithms()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Notice', 'Compression algorithms not supported: unsupported-algorithm');
        $ssh = $this->createSSHMock();
        $ssh->setCompressionAlgorithms(array(
            'unsupported-algorithm'
        ));
    }

    /**
     * @return \phpseclib\Net\SSH2
     */
    protected function createSSHMock()
    {
        return $this->getMockBuilder('phpseclib\Net\SSH2')
            ->disableOriginalConstructor()
            ->setMethods(array('__destruct'))
            ->getMock();
    }
}
