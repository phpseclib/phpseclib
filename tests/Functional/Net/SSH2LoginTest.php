<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Functional\Net;

use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Net\SSH2;
use phpseclib4\Tests\PhpseclibFunctionalTestCase;

class SSH2LoginTest extends PhpseclibFunctionalTestCase
{
    public function testKeyboardInteractiveLogin(): void
    {
        $ssh = new SSH2($this->getEnv('SSH_HOSTNAME'), 23);

        $username = $this->getEnv('SSH_USERNAME');
        $password = $this->getEnv('SSH_PASSWORD');
        $this->assertTrue(
            $ssh->login($username, $password),
            'SSH2 login using keyboard-interactive auth failed.'
        );
    }

    public function test2FALogin(): void
    {
        $ssh = new SSH2($this->getEnv('SSH_HOSTNAME'), 24);

        $username = $this->getEnv('SSH_USERNAME');
        $password = $this->getEnv('SSH_PASSWORD');
        $key = PublicKeyLoader::load(file_get_contents($this->getEnv('PHPSECLIB_SSH_HOME') . '/.ssh/id_rsa'));
        $this->assertTrue(
            $ssh->login($username, $password, $key),
            'SSH2 login using 2FA (keyboard interactive + publickey) auth failed.'
        );
    }
}
