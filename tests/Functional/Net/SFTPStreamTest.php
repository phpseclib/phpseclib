<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2015 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib3\Tests\Functional\Net;

use phpseclib3\Net\SFTP\Stream;
use phpseclib3\Net\SSH2;

class SFTPStreamTest extends SFTPTestCase
{
    public static function setUpBeforeClass(): void
    {
        Stream::register();
        parent::setUpBeforeClass();
    }

    public function testFopenFcloseCreatesFile(): void
    {
        $context = stream_context_create([
            'sftp' => ['session' => $this->sftp],
        ]);
        $fp = fopen($this->buildUrl('fooo.txt'), 'wb', false, $context);
        $this->assertIsResource($fp);
        fclose($fp);
        $this->assertSame(0, $this->sftp->filesize('fooo.txt'));
    }

    /**
     * @group github778
     */
    public function testFilenameWithHash(): void
    {
        $context = stream_context_create([
            'sftp' => ['session' => $this->sftp],
        ]);
        $fp = fopen($this->buildUrl('te#st.txt'), 'wb', false, $context);
        fwrite($fp, 'zzzz');
        fclose($fp);

        $this->assertContains('te#st.txt', $this->sftp->nlist());
    }

    /**
     * Tests connection reuse functionality same as ssh2 extension:
     * {@link http://php.net/manual/en/wrappers.ssh2.php#refsect1-wrappers.ssh2-examples}
     */
    public function testConnectionReuse(): void
    {
        $originalConnectionsCount = count(SSH2::getConnections());
        $session = $this->sftp;
        $dirs = scandir("sftp://$session/");
        $this->assertCount($originalConnectionsCount, SSH2::getConnections());
        $this->assertEquals(['.', '..'], array_slice($dirs, 0, 2));
    }

    /**
     * @group github1552
     */
    public function testStreamSelect(): void
    {
        $context = stream_context_create([
            'sftp' => ['session' => $this->sftp],
        ]);
        $fp = fopen($this->buildUrl('fooo.txt'), 'wb', false, $context);
        $read = [$fp];
        $write = $except = null;
        stream_select($read, $write, $except, 0);
    }

    protected function buildUrl($suffix): string
    {
        return sprintf(
            'sftp://via-context/%s/%s',
            $this->sftp->pwd(),
            $suffix
        );
    }
}
