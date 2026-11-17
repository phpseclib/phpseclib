<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014-2026 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Net;

use phpseclib4\Net\SFTP;
use phpseclib4\Net\SFTP\Stream;
use phpseclib4\Net\SSH2;
use phpseclib4\Tests\PhpseclibTestCase;

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

    public function testMetadataUsesNegotiatedSFTPVersion(): void
    {
        $this->assertMetadataBehavior(4, STREAM_META_OWNER_NAME, 'owner', 'chown', true);
        $this->assertMetadataBehavior(4, STREAM_META_GROUP_NAME, 'group', 'chgrp', true);
        $this->assertMetadataBehavior(5, STREAM_META_OWNER, 1000, 'chown', false);
        $this->assertMetadataBehavior(5, STREAM_META_GROUP, 1000, 'chgrp', false);
    }

    public function testParsePathAcceptsInvokableNotificationWithSession(): void
    {
        $sftp = new class extends SFTP {
            public function __construct()
            {
            }
        };
        $notification = new class {
            public function __invoke(mixed ...$args): void
            {
            }
        };
        $stream = new class extends Stream {
            public function parsePath(string $path): ?string
            {
                return $this->parse_path($path);
            }
        };
        $stream->context = stream_context_create(
            ['sftp' => ['session' => $sftp]],
            ['notification' => $notification]
        );

        $this->assertSame(
            '/file?query=value#fragment',
            $stream->parsePath('sftp://example.test/file?query=value#fragment')
        );
    }

    public function testParsePathRejectsNonSftpConnectionResource(): void
    {
        $ssh2 = new class extends SSH2 {
            public function __construct()
            {
            }
        };
        $connections = new \ReflectionProperty(SSH2::class, 'connections');
        $previous = $connections->isInitialized() ? $connections->getValue() : [];
        $id = $ssh2->getResourceId();
        $connections->setValue(null, [$id => \WeakReference::create($ssh2)]);

        try {
            $stream = new class extends Stream {
                public function parsePath(string $path): ?string
                {
                    return $this->parse_path($path);
                }
            };

            $this->assertNull($stream->parsePath("sftp://$id/file"));
        } finally {
            $connections->setValue(null, $previous);
        }
    }

    private function assertMetadataBehavior(
        int $version,
        int $option,
        int|string $id,
        string $method,
        bool $expectedResult
    ): void {
        $sftp = new class ($version) extends SFTP {
            public int $testVersion;

            /** @var list<string> */
            public array $operations = [];

            public function __construct(int $version)
            {
                $this->testVersion = $version;
            }

            public function getNegotiatedVersion(): int
            {
                return $this->testVersion;
            }

            public function chown(string $filename, int|string $uid, bool $recursive = false): void
            {
                $this->operations[] = 'chown';
            }

            public function chgrp(string $filename, int|string $gid, bool $recursive = false): void
            {
                $this->operations[] = 'chgrp';
            }
        };

        $stream = new Stream();
        $stream->context = stream_context_create([
            'sftp' => ['session' => $sftp],
        ]);

        $actual = $stream->__call('stream_metadata', ['sftp://example.test/file', $option, $id]);
        $this->assertSame($expectedResult, $actual);
        $this->assertSame($expectedResult ? [$method] : [], $sftp->operations);
    }
}
