<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2015-2026 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Functional\Net;

use phpseclib4\Net\SFTP\Stream;
use phpseclib4\Net\SSH2;

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

    #[\PHPUnit\Framework\Attributes\Group('github778')]
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

    #[\PHPUnit\Framework\Attributes\Group('github1552')]
    public function testStreamSelect(): void
    {
        $context = stream_context_create([
            'sftp' => ['session' => $this->sftp],
        ]);
        $fp = fopen($this->buildUrl('fooo.txt'), 'wb', false, $context);
        $this->assertIsResource($fp);
        $read = [$fp];
        $write = $except = null;
        stream_select($read, $write, $except, 0);
    }

    public function testReadZero(): void
    {
        $context = stream_context_create([
            'sftp' => ['session' => $this->sftp],
        ]);
        $this->sftp->put('zero.txt', '0');
        $this->assertSame('0', file_get_contents($this->buildUrl('zero.txt'), false, $context));

        $this->sftp->put('zero-tail.txt', str_repeat('a', 8192) . '0');
        $this->assertSame(str_repeat('a', 8192) . '0', file_get_contents($this->buildUrl('zero-tail.txt'), false, $context));
    }

    protected function buildUrl($suffix): string
    {
        return sprintf(
            'sftp://via-context/%s/%s',
            $this->sftp->pwd(),
            $suffix
        );
    }

    public function testTouch(): void
    {
        $session = $this->sftp;
        $pwd = $this->sftp->pwd();
        $fileName = "sftp://$session/$pwd/touched.txt";
        $this->assertFalse(file_exists($fileName));
        touch($fileName);
        $this->assertTrue(file_exists($fileName));
        $this->assertEquals(0, filesize($fileName));
    }

    public function testFeof(): void
    {
        $this->sftp->put('eof.txt', 'hello world');
        $context = stream_context_create([
            'sftp' => ['session' => $this->sftp],
        ]);
        $fp = fopen($this->buildUrl('eof.txt'), 'rb', false, $context);

        $data = '';
        // capped so that a missing EOF fails the test instead of hanging it
        for ($i = 0; $i < 10 && !feof($fp); $i++) {
            $data .= fread($fp, 8192);
        }

        $this->assertTrue(feof($fp), 'Failed asserting that feof() is true after reading the whole file');
        $this->assertSame('hello world', $data);
        fclose($fp);
    }
}
