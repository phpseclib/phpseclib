<?php

/** @var iterable<SplFileInfo> $files */
$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__));
foreach ($files as $file) {
    if ($file->getExtension() === 'php' && $file->getPathname() !== __FILE__) {
        $fileContents = file_get_contents($file->getPathname());
        if ($fileContents === false) {
            throw new RuntimeException('file_get_contents() failed: ' . $file->getPathname());
        }
        $patternToReplacementMap = [
            '~ function assertMatchesRegularExpression\(\$pattern, \$string, \$message = \'\'\)~' => ' function _assertMatchesRegularExpression(string $pattern, string $string, string $message = \'\')',
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
