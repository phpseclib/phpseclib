<?php

/**
 * @author Vladimir Gaydamaka <vladimir.gaydamaka@gmail.com>
 * @copyright 20019 Vladimir Gaydamaka
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Net\SFTP;

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
      $this->assertTrue($this->sftp->login(
        $this->getEnv('SSH_USERNAME'),
        $this->getEnv('SSH_PASSWORD')
      ));
    }
}
