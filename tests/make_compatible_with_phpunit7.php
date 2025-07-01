<?php

declare(strict_types=1);

/** @var iterable<SplFileInfo> $files */
$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__));
foreach ($files as $file) {
    if ($file->getExtension() === 'php' && $file->getPathname() !== __FILE__) {
        $fileContents = file_get_contents($file->getPathname());
        if ($fileContents === false) {
            throw new RuntimeException('file_get_contents() failed: ' . $file->getPathname());
        }
        $patternToReplacementMap = [
            '~ function setUpBeforeClass\(\)~' => ' function setUpBeforeClass(): void',
            '~ function tearDownAfterClass\(\)~' => ' function tearDownAfterClass(): void',
            '~ function setUp\(\)~' => ' function setUp(): void',
            '~ function tearDown\(\)~' => ' function tearDown(): void',
            '~ function assertIsArray\(\$actual, \$message = \'\'\)~' => ' function _assertIsArray($actual, string $message = \'\')',
            '~ function assertIsResource\(\$actual, \$message = \'\'\)~' => ' function _assertIsResource($actual, string $message = \'\')',
            '~ function assertIsObject\(\$actual, \$message = \'\'\)~' => ' function _assertIsObject($actual, string $message = \'\')',
            '~ function assertIsString\(\$actual, \$message = \'\'\)~' => ' function _assertIsString($actual, string $message = \'\')',
            '~ function assertStringContainsString\(\$needle, \$haystack, \$message = \'\'\)~' => ' function _assertStringContainsString(string $needle, string $haystack, string $message = \'\')',
            '~ function assertStringNotContainsString\(\$needle, \$haystack, \$message = \'\'\)~' => ' function _assertStringNotContainsString(string $needle, string $haystack, string $message = \'\')',
        ];
        $updatedFileContents = preg_replace(
            array_keys($patternToReplacementMap),
            array_values($patternToReplacementMap),
            $fileContents
        );
        if (file_put_contents($file->getPathname(), $updatedFileContents) === false) {
            throw new RuntimeException('file_put_contents() failed: ' . $file->getPathname());
        }
    }
}
