<?php

declare(strict_types=1);

namespace Rector\Tests\TypeDeclaration\Rector\PublicKeyLoaderChained;

use Rector\Testing\PHPUnit\AbstractRectorTestCase;

final class PublicKeyLoaderChainedTest extends AbstractRectorTestCase
{
    /**
     * @dataProvider provideData()
     */
    public function test(string $filePath): void
    {
        $this->doTestFile($filePath);
    }

    public static function provideData(): \Iterator
    {
        return self::yieldFilesFromDirectory(__DIR__ . '/Fixture');
    }

    public function provideConfigFilePath(): string
    {
        return __DIR__ . '/config/rule.php';
    }
}
