<?php

/**
 * @author Vladimir Gaydamaka <vladimir.gaydamaka@gmail.com>
 * @copyright 20019 Vladimir Gaydamaka
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Net\SFTP;
use PHPUnit\Framework\Error\Warning;

class SFTPWrongServerTest extends Functional_Net_SFTPTestCase
{
    public function setUp()
    {
      parent::setUp();
      $this->scratchDir = uniqid('phpseclib-sftp-scratch-');

      $this->sftp = new SFTP($this->getEnv('SSH_WRONG_HOSTNAME'));
    }

    public function testLogin()
    {
      try {
        $this->sftp->login(
          $this->getEnv('SSH_USERNAME'),
          $this->getEnv('SSH_PASSWORD')
        );
        $this->fail('Cannot connect to ' . $this->getEnv('SSH_WRONG_HOSTNAME'));
      }
      catch (\PHPUnit\Framework\Error\Error $e) {
        $this->assertSame('Cannot connect to ' . $this->getEnv('SSH_WRONG_HOSTNAME') .':22. Error 0. php_network_getaddresses: getaddrinfo failed: Name or service not known', $e->getMessage());
      }
    }
}
